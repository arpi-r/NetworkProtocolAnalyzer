const electron = require('electron');
const url = require('url');
const path = require('path');
const exec = require('child_process').exec;
const fs = require('fs'); 
const readline = require('readline');
const { protocol } = require('electron');


packets = []
numberOfPackets = 0
bgcolor = [
    'rgba(255, 99, 132, 0.2)',
    'rgba(54, 162, 235, 0.2)',
    'rgba(255, 206, 86, 0.2)',
    'rgba(75, 192, 192, 0.2)',
]

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

ipcMain.on("btngraphclick", function (event) {
    console.log('here')
    var graphInfo = giveInfo('all');
    setTimeout(() => {
        event.sender.send("btngraphclick-task-finished", "yes", graphInfo, bgcolor);
    }, 1000);
    
});

ipcMain.on("btngraphincomingclick", function (event) {
    var graphInfo = giveInfo('incoming');
    setTimeout(() => {
        event.sender.send("btngraphincomingclick-task-finished", "yes", graphInfo, bgcolor);
    }, 1000);
    
});

ipcMain.on("btngraphoutgoingclick", function (event) {
    var graphInfo = giveInfo('outgoing');
    setTimeout(() => {
        event.sender.send("btngraphoutgoingclick-task-finished", "yes", graphInfo, bgcolor);
    }, 1000);
    
});

function giveInfo(param) {
    graphInfo = readFromPacketInfo('./ddd');
    if(param == 'all') {
        console.log(graphInfo.protocols);
        return graphInfo.protocols;
    }
    else if(param == 'incoming')
        return graphInfo.protocolsIncoming;
    else if(param == 'outgoing')
        return graphInfo.protocolsOutgoing;
}

function readFromPacketInfo(filename) {
    var lineno = 0;
    thisPCMAC = 'a0:af:bd:16:5c:79';
    protocols = {
        'UDP': 0,
        'ICMP': 0,
        'TCP': 0,
        'DHCP': 0,
    }

    protocolsIncoming = {
        'UDP': 0,
        'ICMP': 0,
        'TCP': 0,
        'DHCP': 0,
    }

    protocolsOutgoing = {
        'UDP': 0,
        'ICMP': 0,
        'TCP': 0,
        'DHCP': 0,
    }
    var lineReader = require('readline').createInterface({
        input: require('fs').createReadStream(filename)
    });
    var currPacket = {
        srcIP: '',
        destIP: '',
        srcMAC: '',
        destMAC: '',
        protocol: '',
    }
    var inCurrPacket = 0
    lineReader.on('line', function (line) {
        // console.log('1');
        if(line[0] == '=') {
            // console.log('2');
            numberOfPackets++;
            inCurrPacket = 1;
            packets.push(currPacket);
            currPacket = {
                srcIP: '',
                destIP: '',
                srcMAC: '',
                destMAC: '',
                protocol: '',
            }
        }
        else if(inCurrPacket == 1) {
            // console.log('3');
            line = line.split(': ');
            value = '';
            if(typeof line[1] !== 'undefined')
                value = line[1].trim();
            key = '';
            if(typeof line[0] !== 'undefined')
                key = line[0].trim();
            // console.log(key)
            
            if(key == 'Desination MAC address') {
                currPacket.destMAC = value;
            }
            else if(key == 'Source MAC address') {
                currPacket.srcMAC = value;
            }
            else if(key == 'Source IP Address') {
                currPacket.srcIP = value;
            }
            else if(key == 'Destination IP Address') {
                currPacket.destIP = value;
            }
            else if(key == 'Protocol') {
                if(value == '01')
                    currPacket.protocol = 'ICMP';
                else if(value == '11')
                    currPacket.protocol = 'UDP';
                else if(value='06')
                    currPacket.protocol = 'TCP';
            }
        }
        // console.log(packets);
        // console.log(numberOfPackets);
    }).on('close', function() {
        // console.log(packets);
        //read through all packets
        var i=0;
        for(i=0;i<packets.length;i++) {
            
            currProto = packets[i].protocol;
            protocols[currProto] += 1;
            // console.log(packets[i].srcMAC);
            if(packets[i].srcMAC == thisPCMAC) {
                protocolsOutgoing[currProto] += 1;
            }
            if(packets[i].destMAC == thisPCMAC) {
                protocolsIncoming[currProto] += 1;
            }
        }
    });
    return {
        'protocols': protocols,
        'protocolsIncoming': protocolsIncoming,
        'protocolsOutgoing': protocolsOutgoing,
    }
}