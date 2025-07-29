document.addEventListener('DOMContentLoaded', function() {
    const tutorsContainer = document.getElementById('tutors-container');
    const loadMoreBtn = document.getElementById('load-more-btn');
    
    if (loadMoreBtn) {
        let offset = 4; // Start after the initial 4 tutors
        
        loadMoreBtn.addEventListener('click', function() {
            // Disable button and show loading state
            loadMoreBtn.disabled = true;
            loadMoreBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
            
            fetch(`/load-more-tutors?offset=${offset}`)
                .then(response => {
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    return response.json();
                })
                .then(data => {
                    // Append new tutors with animation
                    data.tutors.forEach((tutor, index) => {
                        setTimeout(() => {
                            const tutorCard = createTutorCard(tutor);
                            tutorsContainer.appendChild(tutorCard);
                            tutorCard.querySelector('.tutor-profile').classList.add('show');
                        }, index * 100); // 100ms delay between each
                    });
                    
                    // Update button text
                    loadMoreBtn.textContent = `Load ${data.tutors.length} More Tutors`;
                    
                    offset = data.new_offset;
                    if (!data.has_more) loadMoreBtn.style.display = 'none';
                })
                .catch(error => {
                    console.error('Error:', error);
                    loadMoreBtn.innerHTML = 'Error - Click to Try Again';
                })
                .finally(() => {
                    if (loadMoreBtn.style.display !== 'none') {
                        loadMoreBtn.disabled = false;
                    }
                });
        });
    }

    function createTutorCard(tutor) {
        const colDiv = document.createElement('div');
        colDiv.className = 'col-xs-12 col-sm-6 col-md-4 col-lg-4';
        
        // Generate star rating HTML
        let stars = '';
        for (let i = 1; i <= 5; i++) {
            if (i <= Math.floor(tutor.rating)) {
                stars += '<i class="fas fa-star"></i>';
            } else if (i - 0.5 <= tutor.rating) {
                stars += '<i class="fas fa-star-half-alt"></i>';
            } else {
                stars += '<i class="far fa-star"></i>';
            }
        }
        
        // Generate subjects HTML
        const subjects = tutor.subjects.map(subj => `<span class="subject-tag">${subj}</span>`).join('');
        
        colDiv.innerHTML = `
            <div class="tutor-profile panel panel-default">
                <div class="panel-body text-center">
                    ${tutor.badge ? `<div class="tutor-badge">${tutor.badge}</div>` : ''}
                    <img src="${tutor.image}" class="img-responsive img-circle tutor-img" alt="${tutor.name}">
                    <h3 class="tutor-name">${tutor.name}</h3>
                    <p class="tutor-education">${tutor.education}</p>
                    <div class="tutor-rating">
                        ${stars}
                        <span>${tutor.rating} (${tutor.review_count} reviews)</span>
                    </div>
                    <p class="tutor-experience"><strong>Experience:</strong> ${tutor.experience}</p>
                    <div class="tutor-subjects">
                        ${subjects}
                    </div>
                    <p class="tutor-quote"><em>"${tutor.quote}"</em></p>
                    <div class="tutor-actions">
                        <a href="/tutor/${tutor.id}" class="btn btn-primary tutor-link">View Profile</a>
                        <a href="#" class="btn btn-outline tutor-link">Book Trial</a>
                    </div>
                </div>
            </div>
        `;
        
        return colDiv;
    }
});