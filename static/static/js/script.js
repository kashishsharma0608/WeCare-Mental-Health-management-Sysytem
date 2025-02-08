document.addEventListener('DOMContentLoaded', function() {
    const moodForm = document.getElementById('mood-form');
    if (moodForm) {
        moodForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const selectedMood = moodForm.querySelector('input[name="mood"]:checked');

            if (selectedMood) {
                // If you're handling the form submission via fetch or axios, you can do it here
                // For now, we will just display a message
                alert("Mood recorded! Your current mood is: " + selectedMood.value);
            } else {
                alert("Please select a mood before submitting.");
            }
        });
    }
});
