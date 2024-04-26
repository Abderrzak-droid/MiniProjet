// Assuming you're using jQuery
$(document).ready(function() {
    var intervalId = setInterval(function() {
        $.ajax({
            url: '/check-task-result/',
            type: 'GET',
            dataType: 'json',
            success: function(data) {
                if (data.status === 'success') {
                    clearInterval(intervalId);
                    displayNotification(data.message, data.result);
                } else if (data.status === 'pending') {
                    displayNotification(data.message);
                } else {
                    clearInterval(intervalId);
                    displayErrorNotification(data.message);
                }
            },
            error: function() {
                clearInterval(intervalId);
                displayErrorNotification('An error occurred while checking the task status.');
            }
        });
    }, 5000); // Check for task status every 5 seconds
});

function displayNotification(message, result) {
    // Display a notification with the provided message and result (if available)
    console.log(message);
    if (result) {
        console.log('Result:', result);
    }
}

function displayErrorNotification(message) {
    // Display an error notification with the provided message
    console.error(message);
}