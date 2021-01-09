// generate password on load
window.addEventListener('load', displayGeneratedPassword);

// update length input
document.getElementById('lengthRange').addEventListener('input', function() {
	document.getElementById('lengthNumber').value = this.value; 
	validateInput();
});
document.getElementById('lengthNumber').addEventListener('input', function() {
	document.getElementById('lengthRange').value = this.value; 
	validateInput();
});

// validate entered length
document.getElementById('lengthNumber').addEventListener('input', function() {
	length = this.value;
	if (length.length > 3) {
		document.getElementById('lengthNumber').value = length.substring(0,3);
	} else if (length < 1) {
		document.getElementById('lengthNumber').value = 1;
		document.getElementById('lengthRange').value = 1;
	}
});

// check if at least one category of characters selected
Array.from(document.getElementsByClassName('custom-control-input')).forEach(checkbox => {
	checkbox.addEventListener('click', function() {
		let lower = document.getElementById('lower').checked;
		let upper = document.getElementById('upper').checked;
		let numbers = document.getElementById('numbers').checked;
		let special = document.getElementById('special').checked;
		console.log(lower, upper, numbers, special);
		if (lower === false && upper === false && numbers === false && special === false) {
			document.getElementById('generateButton').disabled = true;
			// document.getElementById('generateButton').className = 
		} else {
			document.getElementById('generateButton').disabled = false;
		}
	});
});

// generate and display password
document.getElementById('generateButton').addEventListener('click', displayGeneratedPassword);
function displayGeneratedPassword() {
	let length = document.getElementById('lengthNumber').value;
	let lower = document.getElementById('lower').checked;
	let upper = document.getElementById('upper').checked;
	let numbers = document.getElementById('numbers').checked;
	let special = document.getElementById('special').checked;

	password = generatePassword(length, lower, upper, numbers, special);

	document.getElementById('generatedPassword').value = password;
	document.getElementById('message').innerHTML = '';
}

// copy password to clipboard
document.getElementById('copyButton').addEventListener('click', function() {
	let copyText = document.getElementById('generatedPassword');
	copyText.select();
	if (copyText.value) {
	  copyText.setSelectionRange(0, 999); /*For mobile devices*/
	  document.execCommand('copy');
	  document.getElementById('message').innerHTML = 'Copied to clipboard!'
	} else {
	  document.getElementById('message').innerHTML = 'Nothing to copy!'
	}
});

// select generated password on click
document.getElementById('generatedPassword').addEventListener('click', function() { this.select() });


function generatePassword(length=16, lower=true, upper=true, numbers=true, special=true) {
	const lowchars = 'qwertyuiopasdfghjklzxcvbnm';
    const upchars = 'QWERTYUIOPASDFGHJKLZXCVBNM';
    const nums = '1234567890';
    const specialchars = '!@#$%^&*()';

    length = length.substring(0,3);

    let scope = '';
    if (lower) {
        scope += lowchars;
    }
    if (upper) {
        scope += upchars;
    }
    if (numbers) {
        scope += nums;
    }
    if (special) {
        scope += specialchars;
    }

    psw = '';
    if (scope) {
    	for (let i = 0; i < length; i++) {
            psw += scope.charAt(Math.floor(Math.random() * (scope.length - 1)));
    	}
    }
    return psw;
}