// JavaScript function to generate 6 random unique values in order and populate form
function luckyDip() {

    // create empty set
    let draw = new Set();


    // while set does not contain 6 values, create a random value between 1 and 60
    while (draw.size < 6) {
        min = Math.ceil(1);
        max = Math.floor(60);
        //create a typed array of 32-bit unsigned int with length 1 (as generating one number at a time)
        randomBuffer = new Uint32Array(1);
        //fill the array with a cryptographically secure 32-bit unsigned int between the range 0 to 4294967295
        window.crypto.getRandomValues(randomBuffer)
        //converting the int to a floating point number between 0 and 0.99... and then using that and the min and max to
        //generate result to between 1 and 60
        value = Math.floor((randomBuffer[0] / (0xFFFFFFFF)) * (max - min + 1) + min);

        // sets cannot contain duplicates so value is only added if it does not exist in set
        draw.add(value)
    }

    // turn set into an array
    let a = Array.from(draw);

    // sort array into size order
    a.sort(function (a, b) {
        return a - b;
    });

    // add values to fields in create draw form
    for (let i = 0; i < 6; i++) {
        document.getElementById("no" + (i + 1)).value = a[i];
    }
}