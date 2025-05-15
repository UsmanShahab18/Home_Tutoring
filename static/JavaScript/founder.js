document.addEventListener('DOMContentLoaded', () => {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1 // Trigger when 10% of the element is visible
    };

    const observerCallback = (entries, observer) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                
                // Optional: Apply staggered delay if desired for multiple items appearing together
                // Example: if elements are part of a list/grid
                if (entry.target.parentElement.classList.contains('principles-grid') || 
                    entry.target.parentElement.classList.contains('founder-layout')) {
                    // This simple index is based on the order of entries observed in this batch
                    entry.target.style.transitionDelay = `${index * 100}ms`; 
                } else {
                     entry.target.style.transitionDelay = '0ms'; // No delay for single elements
                }
                
                entry.target.style.transitionProperty = 'opacity, transform';
                entry.target.style.transitionDuration = '0.6s'; // Animation duration
                entry.target.style.transitionTimingFunction = 'ease-out';
                
                observer.unobserve(entry.target); // Stop observing once visible
            }
        });
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);

    // Select all elements you want to animate
    const elementsToAnimate = document.querySelectorAll(
        '.founder-image-container, .founder-bio, .section-heading, .principle-item, .impact-text, .impact-icon-showcase'
    );

    elementsToAnimate.forEach(el => {
        observer.observe(el);
    });

    console.log("Founder page animations script loaded and observing elements.");
});