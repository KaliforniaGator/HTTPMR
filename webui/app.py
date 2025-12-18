from fastapi import FastAPI, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
import os
import json
import uuid
import time
import asyncio
import shlex
import sys

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
REPORT_DIR = BASE_DIR

app = FastAPI(title="HTTPMR WebUI")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# In-memory job store: job_id -> {history: [lines], queue: asyncio.Queue(), status, outpath, target}
JOBS = {}
JOBS_LOCK = asyncio.Lock()


def _list_reports():
    return [f for f in os.listdir(REPORT_DIR) if f.endswith('.json') and not f.startswith('.')]


def _get_report_summary(path):
    """Extract summary info from a JSON report."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        tests = data.get('tests', {})
        vuln_count = 0
        if 'cves' in tests:
            vuln_count += len([c for c in tests.get('cves', []) if c.get('vulnerable')])
        headers = tests.get('security_headers', {})
        score = headers.get('score', 0)
        return {
            'url': data.get('url'),
            'timestamp': data.get('timestamp'),
            'vuln_count': vuln_count,
            'security_score': score,
            'size': os.path.getsize(path),
        }
    except Exception as e:
        return {'error': str(e)}


def _normalize_report(path):
    """Ensure reports have a consistent top-level shape with a `tests` dict.
    Converts legacy single-request reports (which contain `test_config`/`response`)
    into a normalized report with `url`, `timestamp`, and `tests` entries so the
    WebUI templates can rely on a consistent schema.
    The original content is preserved under a `legacy` key.
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        # If already normalized, nothing to do
        if isinstance(data, dict) and data.get('tests'):
            return True

        new = {}
        # Preserve original under legacy
        new['legacy'] = data

        # Map known fields
        # Try to find a URL
        url = data.get('url') or (data.get('test_config') or {}).get('url') or (data.get('response') or {}).get('url')
        new['url'] = url
        new['timestamp'] = data.get('timestamp') or data.get('test_config', {}).get('timestamp') or time.strftime('%Y-%m-%d %H:%M:%S')

        tests = {}
        # If this was an auto_mode report (has tests already but at top-level), move it
        if 'tests' in data:
            tests = data['tests']
        else:
            # Single-request report: include under a 'general' test
            general = {
                'test_config': data.get('test_config'),
                'response': data.get('response'),
                'analysis': data.get('analysis')
            }
            if data.get('wordpress_analysis'):
                tests['wordpress'] = data.get('wordpress_analysis')
            tests['general'] = general

        new['tests'] = tests

        # Write back normalized report (overwrite)
        with open(path, 'w') as f:
            json.dump(new, f, indent=2)

        # Try writing SARIF if exporter available
        try:
            import sarif_exporter
            sarif = sarif_exporter.convert_report_to_sarif(new)
            sarif_path = path.replace('.json', '.sarif.json')
            with open(sarif_path, 'w') as sf:
                json.dump(sarif, sf, indent=2)
        except Exception:
            pass

        return True
    except Exception:
        return False


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    files = _list_reports()
    reports = []
    for f in sorted(files, reverse=True):
        path = os.path.join(REPORT_DIR, f)
        summary = _get_report_summary(path)
        reports.append({'filename': f, 'summary': summary})
    return templates.TemplateResponse('dashboard.html', {"request": request, "reports": reports})


@app.post("/upload")
async def upload_report(request: Request, file: UploadFile = File(...)):
    contents = await file.read()
    dest = os.path.join(REPORT_DIR, file.filename)
    with open(dest, 'wb') as f:
        f.write(contents)
    return RedirectResponse(url='/', status_code=303)


@app.post('/run')
async def run_scan(request: Request):
    form = await request.form()
    target = form.get('target')
    mode = form.get('mode') or 'auto'

    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)

    # sanitize filename
    safe_target = ''.join(c for c in target if c.isalnum() or c in ('-', '_', '.'))
    timestamp = str(int(asyncio.get_event_loop().time()))
    outfilename = f"scan_{safe_target}_{timestamp}.json"
    outpath = os.path.join(REPORT_DIR, outfilename)

    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": target}

    # start background task
    asyncio.create_task(_run_httpmr_job(job_id, target, outpath, mode))

    return JSONResponse({"job_id": job_id, "outpath": outpath})


@app.get('/run/{job_id}', response_class=HTMLResponse)
async def run_page(request: Request, job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return RedirectResponse(url='/', status_code=303)
    return templates.TemplateResponse('run.html', {"request": request, "job_id": job_id, "target": job.get('target'), "outpath": job.get('outpath')})


@app.websocket('/ws/{job_id}')
async def ws_logs(websocket: WebSocket, job_id: str):
    await websocket.accept()
    job = JOBS.get(job_id)
    if not job:
        await websocket.send_text("ERROR: job not found")
        await websocket.close()
        return

    # send history first
    for line in job['history']:
        try:
            await websocket.send_text(line)
        except WebSocketDisconnect:
            return

    # then stream new lines
    q = job['queue']
    try:
        while True:
            line = await q.get()
            await websocket.send_text(line)
            if line.startswith("[JOB_FINISHED]"):
                break
    except WebSocketDisconnect:
        return


async def _run_httpmr_job(job_id: str, target: str, outpath: str, mode: str = 'auto'):
    """Run HTTPMR.py in a subprocess and stream logs to JOBS[job_id]."""
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR.py'), '--auto', '--target', target, '-o', outpath, '--verbose']

    # start subprocess
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    # read lines and push to history and queue
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)

    rc = await proc.wait()
    # try to normalize the report file so the UI sees a consistent structure
    try:
        _normalize_report(outpath)
    except Exception:
        pass

    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc


@app.get('/view', response_class=HTMLResponse)
async def view_report(request: Request, name: str):
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path):
        return templates.TemplateResponse('dashboard.html', {"request": request, "reports": [], "error": 'Report not found'})
    with open(path, 'r') as f:
        data = json.load(f)

    summary = _get_report_summary(path)
    return templates.TemplateResponse('report.html', {"request": request, "report": data, "summary": summary, "report_filename": name})


@app.post('/delete_report')
async def delete_report(request: Request):
    form = await request.form()
    name = form.get('name')
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path) or not path.startswith(REPORT_DIR):
        return JSONResponse({"error": "report not found or invalid path"}, status_code=400)
    
    try:
        os.remove(path)
        # also try to remove companion SARIF if it exists
        sarif_path = path.replace('.json', '.sarif.json')
        if os.path.exists(sarif_path):
            os.remove(sarif_path)
        return JSONResponse({"status": "deleted", "name": name})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post('/convert_sarif')
async def convert_sarif(request: Request):
    form = await request.form()
    name = form.get('name')
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path):
        return JSONResponse({"error": "report not found"}, status_code=400)
    
    try:
        import sarif_exporter
        with open(path, 'r') as f:
            report = json.load(f)
        sarif = sarif_exporter.convert_report_to_sarif(report)
        sarif_path = path.replace('.json', '.sarif.json')
        with open(sarif_path, 'w') as sf:
            json.dump(sarif, sf, indent=2)
        return JSONResponse({"status": "converted", "sarif_path": os.path.basename(sarif_path)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get('/download_sarif')
async def download_sarif(name: str):
    """Download a SARIF file (if it exists)."""
    path = os.path.join(REPORT_DIR, name.replace('.json', '.sarif.json'))
    if not os.path.exists(path):
        return JSONResponse({"error": "sarif not found"}, status_code=404)
    return FileResponse(path, media_type='application/json', filename=os.path.basename(path))


@app.post('/run_tester')
async def run_tester(request: Request):
    form = await request.form()
    report = form.get('report')
    if not report or not os.path.exists(os.path.join(REPORT_DIR, report)):
        return JSONResponse({"error": "report not found"}, status_code=400)

    safe_report = report
    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    outpath = os.path.join(REPORT_DIR, f"tester_{safe_report}")
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": report}
    asyncio.create_task(_run_tester_job(job_id, report, outpath))
    return JSONResponse({"job_id": job_id, "outpath": outpath})


async def _run_tester_job(job_id: str, report: str, outpath: str):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR_Tester.py'), '--report', os.path.join(REPORT_DIR, report), '-o', outpath]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)
    rc = await proc.wait()
    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc



@app.post("/upload")
async def upload_report(request: Request, file: UploadFile = File(...)):
    contents = await file.read()
    dest = os.path.join(REPORT_DIR, file.filename)
    with open(dest, 'wb') as f:
        f.write(contents)
    return RedirectResponse(url='/', status_code=303)


@app.post('/run')
async def run_scan(request: Request):
    form = await request.form()
    target = form.get('target')
    mode = form.get('mode') or 'auto'

    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)

    # sanitize filename
    safe_target = ''.join(c for c in target if c.isalnum() or c in ('-', '_', '.'))
    timestamp = str(int(asyncio.get_event_loop().time()))
    outfilename = f"scan_{safe_target}_{timestamp}.json"
    outpath = os.path.join(REPORT_DIR, outfilename)

    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": target}

    # start background task
    asyncio.create_task(_run_httpmr_job(job_id, target, outpath, mode))

    return JSONResponse({"job_id": job_id, "outpath": outpath})


@app.get('/run/{job_id}', response_class=HTMLResponse)
async def run_page(request: Request, job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return RedirectResponse(url='/', status_code=303)
    return templates.TemplateResponse('run.html', {"request": request, "job_id": job_id, "target": job.get('target'), "outpath": job.get('outpath')})


@app.websocket('/ws/{job_id}')
async def ws_logs(websocket: WebSocket, job_id: str):
    await websocket.accept()
    job = JOBS.get(job_id)
    if not job:
        await websocket.send_text("ERROR: job not found")
        await websocket.close()
        return

    # send history first
    for line in job['history']:
        try:
            await websocket.send_text(line)
        except WebSocketDisconnect:
            return

    # then stream new lines
    q = job['queue']
    try:
        while True:
            line = await q.get()
            await websocket.send_text(line)
            if line.startswith("[JOB_FINISHED]"):
                break
    except WebSocketDisconnect:
        return


async def _run_httpmr_job(job_id: str, target: str, outpath: str, mode: str = 'auto'):
    """Run HTTPMR.py in a subprocess and stream logs to JOBS[job_id]."""
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR.py'), '--auto', '--target', target, '-o', outpath, '--verbose']

    # start subprocess
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    # read lines and push to history and queue
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)

    rc = await proc.wait()
    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc


@app.get('/reports', response_class=HTMLResponse)
async def reports_index(request: Request):
    files = _list_reports()
    return templates.TemplateResponse('reports.html', {"request": request, "reports": files})


@app.get('/view', response_class=HTMLResponse)
async def view_report(request: Request, name: str):
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path):
        return templates.TemplateResponse('index.html', {"request": request, "reports": _list_reports(), "error": 'Report not found'})
    with open(path, 'r') as f:
        data = json.load(f)

    tests = data.get('tests', {})
    vuln_count = 0
    if 'cves' in tests:
        vuln_count += len([c for c in tests.get('cves', []) if c.get('vulnerable')])
    headers = tests.get('security_headers', {})
    score = headers.get('score', 0)

    summary = {
        'url': data.get('url'),
        'timestamp': data.get('timestamp'),
        'vuln_count': vuln_count,
        'security_score': score,
    }

    return templates.TemplateResponse('report.html', {"request": request, "report": data, "summary": summary})


@app.post('/run_tester')
async def run_tester(request: Request):
    form = await request.form()
    report = form.get('report')
    if not report or not os.path.exists(os.path.join(REPORT_DIR, report)):
        return JSONResponse({"error": "report not found"}, status_code=400)

    safe_report = report
    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    outpath = os.path.join(REPORT_DIR, f"tester_{safe_report}")
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": report}
    asyncio.create_task(_run_tester_job(job_id, report, outpath))
    return JSONResponse({"job_id": job_id, "outpath": outpath})


async def _run_tester_job(job_id: str, report: str, outpath: str):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR_Tester.py'), '--report', os.path.join(REPORT_DIR, report), '-o', outpath]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)
    rc = await proc.wait()
    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc