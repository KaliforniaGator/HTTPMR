/**
 * HTTPMR Web UI Interactions & Animations
 * Handles micro-interactions, form submissions, and UI enhancements
 */

class HTTPMRUI {
    constructor() {
        this.init();
    }

    init() {
        this.setupFormEnhancements();
        this.setupAnimations();
        this.setupTooltips();
        this.setupNotifications();
        this.setupLoadingStates();
        this.setupKeyboardShortcuts();
    }

    /**
     * Enhanced form handling with validation and submission
     */
    setupFormEnhancements() {
        // Add input animations
        const inputs = document.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            // Focus animations
            input.addEventListener('focus', () => {
                input.parentElement.classList.add('focused');
            });

            input.addEventListener('blur', () => {
                input.parentElement.classList.remove('focused');
                if (input.value) {
                    input.parentElement.classList.add('has-value');
                } else {
                    input.parentElement.classList.remove('has-value');
                }
            });

            // Check initial value
            if (input.value) {
                input.parentElement.classList.add('has-value');
            }
        });

        // Enhanced form submission
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn && !submitBtn.disabled) {
                    this.setButtonLoading(submitBtn, true);
                }
            });
        });

        // Enter key submission for login forms
        const loginForms = document.querySelectorAll('.auth-form');
        loginForms.forEach(form => {
            form.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const submitBtn = form.querySelector('button[type="submit"]');
                    if (submitBtn && !submitBtn.disabled) {
                        submitBtn.click();
                    }
                }
            });
        });
    }

    /**
     * Setup scroll and entrance animations
     */
    setupAnimations() {
        // Intersection Observer for fade-in animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, observerOptions);

        // Observe elements for animation
        const animateElements = document.querySelectorAll('.card, .report-card, .fade-in');
        animateElements.forEach(el => {
            el.classList.add('animate-on-scroll');
            observer.observe(el);
        });

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    /**
     * Setup tooltip functionality
     */
    setupTooltips() {
        const tooltipElements = document.querySelectorAll('[data-tooltip]');
        
        tooltipElements.forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target);
            });

            element.addEventListener('mouseleave', (e) => {
                this.hideTooltip(e.target);
            });
        });
    }

    showTooltip(element) {
        const text = element.getAttribute('data-tooltip');
        if (!text) return;

        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        tooltip.style.cssText = `
            position: absolute;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            padding: var(--space-sm) var(--space-md);
            border-radius: var(--radius-md);
            font-size: 0.875rem;
            z-index: 1000;
            pointer-events: none;
            opacity: 0;
            transition: opacity var(--transition-fast);
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-primary);
        `;

        document.body.appendChild(tooltip);

        // Position tooltip
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';

        // Fade in
        setTimeout(() => {
            tooltip.style.opacity = '1';
        }, 10);
    }

    hideTooltip(element) {
        const tooltip = document.querySelector('.tooltip');
        if (tooltip) {
            tooltip.style.opacity = '0';
            setTimeout(() => {
                tooltip.remove();
            }, 150);
        }
    }

    /**
     * Notification system
     */
    setupNotifications() {
        // Auto-hide existing alerts
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            if (!alert.classList.contains('alert-persistent')) {
                setTimeout(() => {
                    this.hideAlert(alert);
                }, 5000);
            }

            // Add close button
            const closeBtn = document.createElement('button');
            closeBtn.innerHTML = '×';
            closeBtn.style.cssText = `
                background: none;
                border: none;
                color: inherit;
                font-size: 1.2rem;
                cursor: pointer;
                padding: 0;
                margin-left: auto;
            `;
            closeBtn.addEventListener('click', () => this.hideAlert(alert));
            
            if (!alert.querySelector('.alert-close')) {
                const closeWrapper = document.createElement('div');
                closeWrapper.className = 'alert-close';
                closeWrapper.style.cssText = 'display: flex; align-items: center; justify-content: space-between;';
                closeWrapper.appendChild(alert.firstChild);
                closeWrapper.appendChild(closeBtn);
                alert.insertBefore(closeWrapper, alert.firstChild);
            }
        });
    }

    hideAlert(alert) {
        alert.style.transition = 'opacity var(--transition-normal), transform var(--transition-normal)';
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
            alert.remove();
        }, 250);
    }

    /**
     * Show a notification
     */
    showNotification(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} fade-in`;
        notification.innerHTML = `
            <div class="alert-close">
                <span>${message}</span>
                <button style="background: none; border: none; color: inherit; font-size: 1.2rem; cursor: pointer; padding: 0; margin-left: auto;">×</button>
            </div>
        `;

        // Find or create notification container
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: var(--space-lg);
                right: var(--space-lg);
                z-index: 9999;
                max-width: 400px;
            `;
            document.body.appendChild(container);
        }

        container.appendChild(notification);

        // Add close functionality
        const closeBtn = notification.querySelector('button');
        closeBtn.addEventListener('click', () => this.hideAlert(notification));

        // Auto-hide
        if (duration > 0) {
            setTimeout(() => {
                this.hideAlert(notification);
            }, duration);
        }

        return notification;
    }

    /**
     * Loading states for buttons and forms
     */
    setupLoadingStates() {
        // Add ripple effect to buttons
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(button => {
            button.addEventListener('click', function(e) {
                const ripple = document.createElement('span');
                const rect = this.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;

                ripple.style.cssText = `
                    position: absolute;
                    width: ${size}px;
                    height: ${size}px;
                    left: ${x}px;
                    top: ${y}px;
                    background: rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    transform: scale(0);
                    animation: ripple 0.6s linear;
                    pointer-events: none;
                `;

                this.style.position = 'relative';
                this.style.overflow = 'hidden';
                this.appendChild(ripple);

                setTimeout(() => {
                    ripple.remove();
                }, 600);
            });
        });
    }

    /**
     * Set button loading state
     */
    setButtonLoading(button, loading = true) {
        if (loading) {
            button.disabled = true;
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = '<span class="spinner"></span> Loading...';
        } else {
            button.disabled = false;
            button.innerHTML = button.dataset.originalText || button.innerHTML;
        }
    }

    /**
     * Keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to submit forms
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const activeElement = document.activeElement;
                if (activeElement && activeElement.form) {
                    const submitBtn = activeElement.form.querySelector('button[type="submit"]');
                    if (submitBtn && !submitBtn.disabled) {
                        submitBtn.click();
                    }
                }
            }

            // Escape to close modals/notifications
            if (e.key === 'Escape') {
                const alerts = document.querySelectorAll('.alert');
                alerts.forEach(alert => this.hideAlert(alert));
            }
        });
    }

    /**
     * API helper for fetch requests with loading states
     */
    async apiRequest(url, options = {}) {
        const { showLoading = true, button, onSuccess, onError } = options;
        
        try {
            if (showLoading && button) {
                this.setButtonLoading(button, true);
            }

            const response = await fetch(url, {
                method: 'POST',
                body: options.body,
                ...options
            });

            const data = await response.json();

            if (response.ok) {
                if (onSuccess) onSuccess(data);
                return { success: true, data };
            } else {
                throw new Error(data.error || 'Request failed');
            }
        } catch (error) {
            console.error('API Request Error:', error);
            this.showNotification(error.message, 'error');
            if (onError) onError(error);
            return { success: false, error };
        } finally {
            if (showLoading && button) {
                this.setButtonLoading(button, false);
            }
        }
    }

    /**
     * Confirm dialog with custom styling
     */
    confirm(message, onConfirm, onCancel) {
        const modal = document.createElement('div');
        modal.className = 'confirm-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            opacity: 0;
            transition: opacity var(--transition-normal);
        `;

        const dialog = document.createElement('div');
        dialog.className = 'confirm-dialog';
        dialog.style.cssText = `
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: var(--space-xl);
            max-width: 400px;
            width: 90%;
            box-shadow: var(--shadow-xl);
            transform: scale(0.9);
            transition: transform var(--transition-normal);
        `;

        dialog.innerHTML = `
            <h3 style="margin-bottom: var(--space-md); color: var(--text-primary);">Confirm Action</h3>
            <p style="margin-bottom: var(--space-lg); color: var(--text-secondary);">${message}</p>
            <div style="display: flex; gap: var(--space-md); justify-content: flex-end;">
                <button class="btn btn-secondary" data-action="cancel">Cancel</button>
                <button class="btn btn-danger" data-action="confirm">Confirm</button>
            </div>
        `;

        modal.appendChild(dialog);
        document.body.appendChild(modal);

        // Animate in
        setTimeout(() => {
            modal.style.opacity = '1';
            dialog.style.transform = 'scale(1)';
        }, 10);

        // Handle actions
        const handleAction = (action) => {
            modal.style.opacity = '0';
            dialog.style.transform = 'scale(0.9)';
            
            setTimeout(() => {
                modal.remove();
                if (action === 'confirm' && onConfirm) onConfirm();
                if (action === 'cancel' && onCancel) onCancel();
            }, 250);
        };

        dialog.querySelector('[data-action="confirm"]').addEventListener('click', () => handleAction('confirm'));
        dialog.querySelector('[data-action="cancel"]').addEventListener('click', () => handleAction('cancel'));
        
        // Close on backdrop click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                handleAction('cancel');
            }
        });

        // Close on escape
        const handleEscape = (e) => {
            if (e.key === 'Escape') {
                handleAction('cancel');
                document.removeEventListener('keydown', handleEscape);
            }
        };
        document.addEventListener('keydown', handleEscape);
    }
}

// Add ripple animation to CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    .animate-on-scroll {
        opacity: 0;
        transform: translateY(20px);
        transition: opacity var(--transition-normal), transform var(--transition-normal);
    }
    
    .animate-on-scroll.animate-in {
        opacity: 1;
        transform: translateY(0);
    }
    
    .form-group.focused label {
        color: var(--blue-400);
    }
    
    .form-group.has-value input,
    .form-group.has-value textarea,
    .form-group.has-value select {
        border-color: var(--border-secondary);
    }
`;
document.head.appendChild(style);

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.httpmrUI = new HTTPMRUI();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HTTPMRUI;
}
