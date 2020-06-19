const electron = require('electron');
const url = require('url');
const path = require('path');
const exec = require('child_process').exec;
const fs = require('fs') 

const {app, BrowserWindow, Menu, ipcMain} = electron;

// SET ENC 
process.env.NODE_ENV = 'development';

let mainWindow;

// Listen for app to be ready

app.on('ready', function(){
    // Create new window
    mainWindow = new BrowserWindow({
        webPreferences: {
            nodeIntegration: true
        }
    });
    // Load html into window
    mainWindow.loadURL(url.format({
        pathname: path.join(__dirname, 'mainWindow.html'),
        protocol: 'file:',
        slashes: true
    }));
    // Quit app when closed
    mainWindow.on('closed', function(){
        app.quit();
    });
});

function capture(num){
    exec("rm captured_packets.pcap");
    exec("tshark -c " + num + " -w captured_packets.pcap");
    setTimeout(() => {
        // exec("tshark -x -r ./captured_packets.pcap | sed -n 's/^[0-9a-f][0-9a-f]*  \\(.*  \\) .*/\\1/p' > captured_packets_hex");
        exec("tshark -x -r ./captured_packets.pcap > captured_packets_hex");
        // tshark -w capture-output.pcap
        console.log("capture function done");
    }, num*1000);
}

//ipcMain.on will receive the “btncapclick” info from renderprocess 
ipcMain.on("btncapclick",function (event, num) {
    capture(num);
    // event.sender.send in ipcMain will return the reply to renderprocess
    event.sender.send("btncapclick-task-finished", "yes"); 
});

function parse() {
    // exec("tshark -x -r ./captured_packets.pcap | sed -n \'s/^[0-9a-f][0-9a-f]*  \(.*  \) .*/\1/p\' > captured_packets_hex");
    exec("python3 parse_packets.py > packets_info");
    console.log("parse function done");
}

//ipcMain.on will receive the “btnparseclick” info from renderprocess 
ipcMain.on("btnparseclick",function (event) {
    parse();
    var packetinfo = "";
    setTimeout(() => {
        fs.readFile('./packets_info', 'utf-8', (err, data) => { 
            if (err) throw err;  
            packetinfo = data;
            console.log("Packetinfo file read");
            // event.sender.send in ipcMain will return the reply to renderprocess
            event.sender.send("btnparseclick-task-finished", "yes", packetinfo);
        }); 
    }, 1000); 
});