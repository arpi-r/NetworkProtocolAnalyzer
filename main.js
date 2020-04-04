const electron = require('electron');
const url = require('url');
const path = require('path');
const exec = require('child_process').exec;

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

function capture(){
    exec('tshark -c 5 -w captured_packets.pcap');
    console.log("capture function done");
}

//ipcMain.on will receive the “btncapclick” info from renderprocess 
ipcMain.on("btncapclick",function (event) {
    capture();
    // event.sender.send in ipcMain will return the reply to renderprocess
    event.sender.send("btncapclick-task-finished", "yes"); 
});