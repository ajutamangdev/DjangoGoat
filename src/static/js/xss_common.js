// Common XSS Lab JavaScript Functions

// XSS Detection Patterns (for educational reference only)
function detectXSSPatterns(content) {
    const xssPatterns = [
        /<script[^>]*>/i,
        /<img[^>]*onerror/i,
        /<svg[^>]*onload/i,
        /javascript:/i,
        /alert\s*\(/i,
        /prompt\s*\(/i,
        /confirm\s*\(/i,
        /<iframe/i,
        /onmouseover/i,
        /onclick/i,
        /onfocus/i,
        /onload/i,
        /onerror/i
    ];
    
    return xssPatterns.some(pattern => pattern.test(content));
}

function setupHintToggle() {
    const hintToggle = document.getElementById('hintToggle');
    const hintsSection = document.getElementById('hintsSection');

    if (hintToggle && hintsSection) {
        let hintsVisible = false;

        hintToggle.addEventListener('click', function () {
            hintsVisible = !hintsVisible;

            if (hintsVisible) {
                hintsSection.style.display = 'block';
                hintsSection.style.opacity = '0';
                hintsSection.style.transform = 'translateY(-10px)';

                setTimeout(() => {
                    hintsSection.style.transition = 'all 0.3s ease-out';
                    hintsSection.style.opacity = '1';
                    hintsSection.style.transform = 'translateY(0)';
                }, 50);

                hintToggle.innerHTML = '<i data-lucide="lightbulb" class="h-4 w-4 mr-2 inline group-hover:animate-pulse"></i><span class="font-medium">Hide Hints</span>';
            } else {
                hintsSection.style.opacity = '0';
                hintsSection.style.transform = 'translateY(-10px)';

                setTimeout(() => {
                    hintsSection.style.display = 'none';
                }, 300);

                hintToggle.innerHTML = '<i data-lucide="lightbulb" class="h-4 w-4 mr-2 inline group-hover:animate-pulse"></i><span class="font-medium">Show Hints</span>';
            }

            // Refresh Lucide icons
            if (window.lucide) {
                lucide.createIcons();
            }
        });
    }
}

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    setupHintToggle();
});