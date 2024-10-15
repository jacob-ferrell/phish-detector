


async function getPrediction(url) {
    try {
        const res = await fetch('api/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }, 
            body: JSON.stringify({ url })
        });
        const json = await res.json();
        return json.hasOwnProperty('result') ? json.result : json.error;
    } catch(error) {
        console.log(error);
        return 'Error getting prediction';
    }
}


document.querySelector('#submit').addEventListener('click', () => {
    const url = document.querySelector('#url-input').value;
    getPrediction(url).then(res => displayResult(url, res));
})

function displayResult(url, res) {
    console.log(url, res);
    const urlResult = document.querySelector('#url-result');
    const result = document.querySelector('#result');
    urlResult.textContent = 'URL: ' + url;
    result.textContent = 'Prediction: ' + res;
}

function hideAllGraphs() {
    document.querySelectorAll('.graph').forEach(graph => graph.style.display = 'none');
}
const graphIds = ['heatmap', 'roc-curve', 'confusion-matrix'];
document.querySelectorAll('.graph-button').forEach((button, i) => {
    button.addEventListener('click', () => {
        hideAllGraphs();
        document.querySelector('#' + graphIds[i]).style.display = 'block';
    })
})