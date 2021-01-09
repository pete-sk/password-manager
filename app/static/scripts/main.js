// highlight current item in navbar
let currentUrl = window.location.href;
let items = document.querySelectorAll('.nav-item');
for (i in items) {
  if (items[i].href === currentUrl) {
    items[i].className = 'nav-item active nav-link';
  }
}


// show password when checkbox is checked
function showPassword(i) {
    if (document.querySelector('#showPasswordCheckbox' + i).checked == true) {
      document.querySelector('#passwordField' + i).type = 'text';
    } else {
      document.querySelector('#passwordField' + i).type = 'password';
    }
  }


// copy password to clipboard
function copyToClipboard(i) {
    let copyText = document.getElementById("passwordField" + i);
    let originalType = copyText.type;  /*remeber if password shown or hidden*/
    copyText.type = 'text';
    copyText.select();
    copyText.setSelectionRange(0, 99999); /*For mobile devices*/
    document.execCommand("copy");
    if (originalType == 'password'){
      copyText.type = 'password';
    }
  }


// disable checkbox when master key is provided in password reset
document.querySelector('#master_key').oninput = function() {
    if (document.querySelector('#master_key').value === '') {
        if (document.querySelector('#master_key_file').value === '') {
        document.querySelector('#lost_master_key').disabled = false;
    }
    } else {
        document.querySelector('#lost_master_key').disabled = true;
        document.querySelector('#lost_master_key').checked = false;
    }
}
document.querySelector('#master_key_file').oninput = function(){
    if (document.querySelector('#master_key_file').value === ''){
        document.querySelector('#lost_master_key').disabled = false;
    } else {
        document.querySelector('#lost_master_key').disabled = true;
        document.querySelector('#lost_master_key').checked = false;
    }
}