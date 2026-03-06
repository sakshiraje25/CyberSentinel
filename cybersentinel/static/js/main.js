function autoHideToasts() {
    const toasts = document.querySelectorAll('.toast');
    toasts.forEach((toast) => {
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-4px)';
            setTimeout(() => toast.remove(), 250);
        }, 3500);
    });
}

function showGlobalLoader() {
    const overlay = document.getElementById('global-loader');
    if (overlay) {
        overlay.classList.remove('hidden');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    autoHideToasts();
});

