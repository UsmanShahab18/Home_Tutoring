document.addEventListener('DOMContentLoaded', () => {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1 // At least 10% of the element is visible
    };

    let globalAnimationDelayCounter = 0; // To create a continuous stagger effect across sections

    const observerCallback = (entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                
                // Apply staggered delay based on a global counter for a flowing effect
                // Only apply to items that should be staggered, not section headings themselves directly
                if (entry.target.matches('.step, .feature-item, .testimonial-card, .class-icon, .section-heading-light, .cta-text-light, .cta-button.large')) {
                    entry.target.style.transitionDelay = `${globalAnimationDelayCounter * 100}ms`;
                    globalAnimationDelayCounter++; // Increment for the next observed item in this batch
                }
                
                entry.target.style.transitionProperty = 'opacity, transform';
                entry.target.style.transitionDuration = '0.2s'; // Standard duration
                entry.target.style.transitionTimingFunction = 'ease-out';

                observer.unobserve(entry.target);
            }
        });
        // Reset counter if all current entries processed, or manage it based on batches
        // For simplicity here, it just keeps incrementing.
        // If many items are observed at once, they get staggered delays.
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);

    // Elements to observe
    const elementsToObserve = document.querySelectorAll(
        '.section-heading, .class-icon, .step, .feature-item, .testimonial-card, .section-heading-light, .cta-text-light, .cta-button.large'
    );

    elementsToObserve.forEach(el => {
        observer.observe(el);
    });

    // Reset delay counter when new batch of observations might start (e.g. after initial load)
    // This is a simplified stagger. For perfect ordering, you'd need to query all elements in DOM order.
    // setTimeout(() => { globalAnimationDelayCounter = 0; }, 100); // Example: reset for elements appearing later

    console.log("Index.js loaded and observing all designated elements.");
});