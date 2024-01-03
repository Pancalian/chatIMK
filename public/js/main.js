const socket = io();
// Assuming that users is defined in a higher scope, maybe in your main application logic
const users = {};
console.log(socket.id);
const username = "localStorage.getItem('username')";//benerin ini ntar

if (!username) {
    // Redirect to the login page if the username is empty'
    console.log("P", !socket.id);
    // window.location.href = "/login.html"; benerin ini ntar
} else {
    socket.emit('setUsername', username);
}

$(document).ready(() => {
    //  // Fetch session username
    //  $.ajax({
    //     type: "GET",
    //     url: "/getusername", // Assuming this endpoint returns the session username
    //     success: function (data) {
    //         // Display the session username wherever you want in your HTML
    //         displaySessionUsername(data.username);
    //     },
    //     error: function (error) {
    //         console.error("Error fetching session username:", error);
    //     }
    // });

    // function displaySessionUsername(username) {
    //     // Update the DOM with the session username
    //     // For example, assuming you have a div with id "session-username-display"
    //     $('#session-username-display').text("Welcome, " + username);
    // }
    
    $('#sendButton').click(() => {
        const message = $('#messageInput').val();
        socket.emit('sendMessage', message);
        // Save the message to MongoDB
        $('#messageInput').val('');
    });

    // Event listener for receiving chat history
    socket.on('chatHistory', (chatHistory) => {
        // Display chat history on the client side
        chatHistory.forEach((message) => {
            if (message.user === socket.id) {
                // Your own messages
                displayMessage(`${message.username}: ${message.content}`, 'bg-info text-white', 'justify-content-start');
            } else {
                // Messages from other users (not yourself)
                displayMessage(`${message.username}: ${message.content}`, 'bg-lightgreen text-dark', 'justify-content-end');
            }

        });
    });

    socket.on('userMessage', (data) => {
        // Display the received message in the chat window
        if (data.user === socket.id) {
            // Your own messages
            displayMessage(`${data.username}: ${data.content}`, 'bg-info text-white', 'justify-content-start');
        } else {
            // Messages from other users (not yourself)
            displayMessage(`${data.username}: ${data.content}`, 'bg-lightgreen text-dark', 'justify-content-end');
        }
        //displayMessage(`${data.username}: ${data.content}`, 'bg-info text-white');
    });

    socket.on('serverMessage', (data) => {
        // Display the received server message in the chat window
        displayMessage(`server: ${data.content}`, 'bg-warning text-dark', 'justify-content-start');
    });

    $('#messageInput').keydown((e) => {
        if (e.which === 13) {
            // If the pressed key is Enter (key code 13), simulate a click on the sendButton
            $('#sendButton').click();
        }
    });

    socket.on('userConnected', (data) => {
        // Display a system message for user connection
        displayMessage(`server: ${data.username} connected`, 'bg-warning text-dark', 'justify-content-start');
    });

    socket.on('userDisconnected', (data) => {
        if(data.username == "Unknown"){
            return
        }
        // Display a system message for user disconnection
        displayMessage(`server: ${data.username} disconnected`, 'bg-warning text-dark', 'justify-content-start');

        // Remove the 'username' key from localStorage
        localStorage.removeItem('username');
    });

    function displayMessage(message, style, justify) {
        const timestamp = formatTime(new Date());
        // Check if the message indicates a user connection or disconnection
        const isSystemMessage = message.includes('connected') || message.includes('disconnected');

        // Determine the appropriate styles based on whether it's a system message or a regular message
        const messageStyle = isSystemMessage ? 'bg-light' : style;

        const formattedMessage = `<div class="d-flex ${justify} ${style} p-2 mb-2">${timestamp} - ${message}</div>`;
        $('#chat-messages').append(formattedMessage);
    }

    function formatTime(time) {
        const options = { hour: 'numeric', minute: 'numeric', second: 'numeric' };
        return new Intl.DateTimeFormat('en-US', options).format(time);
    }
});