document.addEventListener('DOMContentLoaded', function() {
    var initialDiv = document.getElementsByClassName('wrapper');
    var duration = 500; // Duration in milliseconds

    setTimeout(function() {
        initialDiv.style.display = 'none';
    }, duration);
});