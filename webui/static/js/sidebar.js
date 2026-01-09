// Reusable Sidebar Component
(function() {
    // Initialize sidebar state - start open by default
    function initSidebar() {
        const body = document.body;
        // Start with sidebar open by default
        const appShell = document.querySelector('.app-shell');
        if (appShell) {
            appShell.style.gridTemplateColumns = '260px minmax(0, 1fr)';
        }
        // Only add backdrop on mobile devices
        if (window.innerWidth <= 992) {
            body.classList.add('sidebar-open');
        }
    }

    function closeSidebar() {
        // First animate the sidebar out
        const body = document.body;
        body.classList.add('sidebar-collapsed');
        body.classList.remove('sidebar-open');
        
        // After animation completes, collapse the grid
        setTimeout(() => {
            if (body.classList.contains('sidebar-collapsed')) {
                const appShell = document.querySelector('.app-shell');
                if (appShell) {
                    appShell.style.gridTemplateColumns = '0 minmax(0, 1fr)';
                }
            }
        }, 400);
    }

    function openSidebar() {
        // First expand the grid, then animate the sidebar in
        const appShell = document.querySelector('.app-shell');
        if (appShell) {
            appShell.style.gridTemplateColumns = '260px minmax(0, 1fr)';
        }
        
        // Only add backdrop on mobile devices
        const body = document.body;
        if (window.innerWidth <= 992) {
            body.classList.add('sidebar-open');
        }
        
        // Then animate the sidebar in
        setTimeout(() => {
            body.classList.remove('sidebar-collapsed');
        }, 50);
    }

    function setupSidebarEvents() {
        const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
        const sidebarToggleMain = document.querySelector('[data-sidebar-toggle-main]');
        const backdrop = document.querySelector('.sidebar-backdrop');

        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                const body = document.body;
                if (body.classList.contains('sidebar-collapsed')) {
                    openSidebar();
                } else {
                    closeSidebar();
                }
            });
        }

        if (sidebarToggleMain) {
            sidebarToggleMain.addEventListener('click', () => {
                openSidebar();
            });
        }

        if (backdrop) {
            backdrop.addEventListener('click', closeSidebar);
        }

        // Handle window resize to adjust backdrop behavior
        window.addEventListener('resize', () => {
            const body = document.body;
            if (window.innerWidth > 992) {
                // Remove backdrop on desktop
                body.classList.remove('sidebar-open');
            } else if (!body.classList.contains('sidebar-collapsed')) {
                // Add backdrop on mobile if sidebar is open
                body.classList.add('sidebar-open');
            }
        });

        // Handle escape key
        document.addEventListener('keyup', (event) => {
            if (event.key === 'Escape') {
                closeSidebar();
            }
        });

        // Close sidebar when clicking on navigation links
        const sidebar = document.querySelector('.tool-sidebar');
        if (sidebar) {
            sidebar.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', closeSidebar);
            });
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            initSidebar();
            setupSidebarEvents();
        });
    } else {
        initSidebar();
        setupSidebarEvents();
    }
})();
