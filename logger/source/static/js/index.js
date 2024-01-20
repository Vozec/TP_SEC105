function getReq(url) {
    return fetch(url, {
        method: 'GET',
    }).then(response => {
        if (!response.ok) {
            throw new Error('Error: ' + response.status);
        }
        return response.json();
    }).catch(error => {
        showErrorNotification('error')
    });
}

function showResetPopup(event) {
    event.stopPropagation();
    new bootstrap.Modal(document.getElementById('resetPopup')).show();
}


function confirmDelete() {
    getReq('/api/reset')
    .then(data => {
        if ('error' in data) {
            console.log('Error: ' + data.error);
        } else {
            location.reload()
        }
    }).catch(error => {
        console.error('Error:', error);
    });
    closeDeletePopup();
}

let target = 0;
let countdown = 10;

const countdownElement = document.getElementById('countdown');
function updateCountdown() {
    countdown--;
    countdownElement.textContent = countdown;
    if (countdown === 0) {
        location.reload();
    }
}
setInterval(updateCountdown, 1000);