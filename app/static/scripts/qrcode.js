
// generate QR code
window.onload = generateQrCode;
function generateQrCode () {
    let secret = document.querySelector('#secret').value
    console.log(secret);
    const Http = new XMLHttpRequest();
    // const url = 'http://127.0.0.1:5000/account/settings/2fa/setup/otp-path/' + secret;
    const url = 'https://' + window.location.hostname + '/account/settings/2fa/setup/otp-path/' + secret;
    console.log(url);
    Http.open("GET", url);
    Http.send();

    Http.onreadystatechange = (e) => {
        console.log(Http.responseText);
        let value = Http.responseText;
        let qrCodeImg = new QRious({
            element: document.querySelector('#otp-qr-code'),
            value: value,
            size: 1000,
            padding: 50
        });
    }
}