document.addEventListener('DOMContentLoaded', function() {

    const accordions = document.querySelectorAll('.accordion');

    accordions.forEach(accordion => {

        accordion.addEventListener('click', function() {

            const faqItem = this.closest('.faq');

            const panel = this.nextElementSibling;

            accordions.forEach(otherAccordion => {
                const otherFaqItem = otherAccordion.closest('.faq');
                const otherPanel = otherAccordion.nextElementSibling;

                if (otherAccordion !== this && otherFaqItem.classList.contains('active')) {
                    otherFaqItem.classList.remove('active');
                    otherAccordion.classList.remove('active');
                    
                    otherPanel.style.maxHeight = null; 
                }
            });

            faqItem.classList.toggle('active');

            this.classList.toggle('active');


            if (panel.style.maxHeight) {
                panel.style.maxHeight = null;
            } else {
                panel.style.maxHeight = panel.scrollHeight + "px";
            }
        });
    });
});