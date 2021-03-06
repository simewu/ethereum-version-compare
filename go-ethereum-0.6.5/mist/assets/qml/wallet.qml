import QtQuick 2.0
import QtQuick.Controls 1.0;
import QtQuick.Layouts 1.0;
import QtQuick.Dialogs 1.0;
import QtQuick.Window 2.1;
import QtQuick.Controls.Styles 1.1
import Ethereum 1.0

import "../ext/filter.js" as Eth
import "../ext/http.js" as Http

ApplicationWindow {
    id: root

    property alias miningButtonText: miningButton.text
    property var ethx : Eth.ethx
    property var web

    width: 1200
    height: 820
    minimumHeight: 300

    title: "Mist"

    // This signal is used by the filter API. The filter API connects using this signal handler from
    // the different QML files and plugins.
    signal messages(var messages, int id);
    function invokeFilterCallback(data, receiverSeed) {
        //var messages = JSON.parse(data)
        // Signal handler
        messages(data, receiverSeed);
	root.web.messages(data, receiverSeed);
    }

    TextField {
        id: copyElementHax
        visible: false
    }

    function copyToClipboard(text) {
        copyElementHax.text = text
        copyElementHax.selectAll()
        copyElementHax.copy()
    }

    // Takes care of loading all default plugins
    Component.onCompleted: {
        var wallet = addPlugin("./views/wallet.qml", {noAdd: true, close: false, section: "ethereum", active: true});
        var browser = addPlugin("./webapp.qml", {noAdd: true, close: false, section: "ethereum", active: true});
	root.web = browser.view;

        addPlugin("./views/transaction.qml", {noAdd: true, close: false, section: "legacy"});
        addPlugin("./views/chain.qml", {noAdd: true, close: false, section: "legacy"});
        addPlugin("./views/info.qml", {noAdd: true, close: false, section: "legacy"});
        addPlugin("./views/pending_tx.qml", {noAdd: true, close: false, section: "legacy"});
        addPlugin("./views/javascript.qml", {noAdd: true, close: false, section: "legacy"});

	addPlugin("./views/jeffcoin/jeffcoin.qml", {noAdd: true, close: false, section: "apps"})

	mainSplit.setView(wallet.view, wallet.menuItem);

        // Call the ready handler
        gui.done();
    }

    function addViews(view, path, options) {
        var views = mainSplit.addComponent(view, options)
        views.menuItem.path = path

        mainSplit.views.push(views);

        if(!options.noAdd) {
            gui.addPlugin(path)
        }

        return views
    }

    function addPlugin(path, options) {
        try {
            if(typeof(path) === "string" && /^https?/.test(path)) {
                console.log('load http')
                Http.request(path, function(o) {
                    if(o.status === 200) {
                        var view = Qt.createQmlObject(o.responseText, mainView, path)
                        addViews(view, path, options)
                    }
                })

                return
            }

            var component = Qt.createComponent(path);
            if(component.status != Component.Ready) {
                if(component.status == Component.Error) {
                    ethx.note("error: ", component.errorString());
                }

                return
            }

            var view = mainView.createView(component, options)
            var views = addViews(view, path, options)

            return views
        } catch(e) {
            ethx.note(e)
        }
    }

    menuBar: MenuBar {
        Menu {
            title: "File"
            MenuItem {
                text: "Import App"
                shortcut: "Ctrl+o"
                onTriggered: {
                    generalFileDialog.show(true, importApp)
                }
            }

            /*
             MenuItem {
                 text: "Browser"
                 onTriggered: eth.openBrowser()
             }
             */

            MenuItem {
                text: "Add plugin"
                onTriggered: {
                    generalFileDialog.show(true, function(path) {
                        addPlugin(path, {close: true, section: "apps"})
                    })
                }
            }

            MenuSeparator {}

            MenuItem {
                text: "Import key"
                shortcut: "Ctrl+i"
                onTriggered: {
                    generalFileDialog.show(true, function(path) {
                        gui.importKey(path)
                    })
                }
            }

            MenuItem {
                text: "Export keys"
                shortcut: "Ctrl+e"
                onTriggered: {
                    generalFileDialog.show(false, function(path) {
                    })
                }
            }

        }

        Menu {
            title: "Developer"
            MenuItem {
                iconSource: "../icecream.png"
                text: "Debugger"
                shortcut: "Ctrl+d"
                onTriggered: eth.startDebugger()
            }

            MenuItem {
                text: "Import Tx"
                onTriggered: {
                    txImportDialog.visible = true
                }
            }

            MenuItem {
                text: "Run JS file"
                onTriggered: {
                    generalFileDialog.show(true, function(path) {
                        eth.evalJavascriptFile(path)
                    })
                }
            }

            MenuItem {
                text: "Dump state"
                onTriggered: {
                    generalFileDialog.show(false, function(path) {
                        // Empty hash for latest
                        gui.dumpState("", path)
                    })
                }
            }

            MenuSeparator {}

            MenuItem {
                id: miningSpeed
                text: "Mining: Turbo"
                onTriggered: {
                    gui.toggleTurboMining()
                    if(text == "Mining: Turbo") {
                        text = "Mining: Normal";
                    } else {
                        text = "Mining: Turbo";
                    }
                }
            }
        }

        Menu {
            title: "Network"
            MenuItem {
                text: "Add Peer"
                shortcut: "Ctrl+p"
                onTriggered: {
                    addPeerWin.visible = true
                }
            }
            MenuItem {
                text: "Show Peers"
                shortcut: "Ctrl+e"
                onTriggered: {
                    peerWindow.visible = true
                }
            }
        }

        Menu {
            title: "Help"
            MenuItem {
                text: "About"
                onTriggered: {
                    aboutWin.visible = true
                }
            }
        }

        Menu {
            title: "GLOBAL SHORTCUTS"
            visible: false
            MenuItem {
                visible: false
                shortcut: "Ctrl+l"
                onTriggered: {
                    url.focus = true
                }
            }
        }
    }

    statusBar: StatusBar {
        height: 32
        RowLayout {
            Button {
                id: miningButton
                text: "Start Mining"
                onClicked: {
                    gui.toggleMining()
                }
            }

            RowLayout {
                Label {
                    id: walletValueLabel

                    font.pixelSize: 10
                    styleColor: "#797979"
                }
            }
        }

        Label {
            y: 6
            objectName: "miningLabel"
            visible: true
            font.pixelSize: 10
            anchors.right: lastBlockLabel.left
            anchors.rightMargin: 5
        }

        Label {
            y: 6
            id: lastBlockLabel
            objectName: "lastBlockLabel"
            visible: true
            text: ""
            font.pixelSize: 10
            anchors.right: peerGroup.left
            anchors.rightMargin: 5
        }

        ProgressBar {
            id: syncProgressIndicator
            visible: false
            objectName: "syncProgressIndicator"
            y: 3
            width: 140
            indeterminate: true
            anchors.right: peerGroup.left
            anchors.rightMargin: 5
        }

        RowLayout {
            id: peerGroup
            y: 7
            anchors.right: parent.right
            MouseArea {
                onDoubleClicked:  peerWindow.visible = true
                anchors.fill: parent
            }

            Label {
                id: peerLabel
                font.pixelSize: 8
                text: "0 / 0"
            }
            Image {
                id: peerImage
                width: 10; height: 10
                source: "../network.png"
            }
        }
    }


    property var blockModel: ListModel {
        id: blockModel
    }

    SplitView {
        property var views: [];

        id: mainSplit
        anchors.fill: parent
        resizing: false

        function setView(view, menu) {
            for(var i = 0; i < views.length; i++) {
                views[i].view.visible = false
                views[i].menuItem.setSelection(false)
            }
            view.visible = true

            //menu.border.color = "#CCCCCC"
            //menu.color = "#FFFFFFFF"
            menu.setSelection(true)
        }

        function addComponent(view, options) {
            view.visible = false
            view.anchors.fill = mainView

            if( !view.hasOwnProperty("iconSource") ) {
                console.log("Could not load plugin. Property 'iconSourc' not found on view.");
                return;
            }

            var menuItem = menu.createMenuItem(view.iconSource, view, options);
            if( view.hasOwnProperty("menuItem") ) {
                view.menuItem = menuItem;
            }

            if( view.hasOwnProperty("onReady") ) {
                view.onReady.call(view)
            }

            if( options.active ) {
                setView(view, menuItem)
            }


            return {view: view, menuItem: menuItem}
        }

        /*********************
         * Main menu.
         ********************/
         Rectangle {
             id: menu
             Layout.minimumWidth: 210
             Layout.maximumWidth: 210
             anchors.top: parent.top
             color: "#ececec"

             Component {
                 id: menuItemTemplate
                 Rectangle {
                     id: menuItem
                     property var view;
                     property var path;
                     property var closable;

                     property alias title: label.text
                     property alias icon: icon.source
                     property alias secondaryTitle: secondary.text
                     function setSelection(on) {
                         sel.visible = on
                     }

                     width: 206
                     height: 28
                     color: "#00000000"

                     anchors {
                         left: parent.left
                         leftMargin: 4
                     }

                     Rectangle {
                         id: sel
                         visible: false
                         anchors.fill: parent
                         color: "#00000000"
                         Rectangle {
                             id: r
                             anchors.fill: parent
                             border.color: "#CCCCCC"
                             border.width: 1
                             radius: 5
                             color: "#FFFFFFFF"
                         }
                         Rectangle {
                             anchors {
                                 top: r.top
                                 bottom: r.bottom
                                 right: r.right
                             }
                             width: 10
                             color: "#FFFFFFFF"

                             Rectangle {
                                 anchors {
                                     left: parent.left
                                     right: parent.right
                                     top: parent.top
                                 }
                                 height: 1
                                 color: "#CCCCCC"
                             }

                             Rectangle {
                                 anchors {
                                     left: parent.left
                                     right: parent.right
                                     bottom: parent.bottom
                                 }
                                 height: 1
                                 color: "#CCCCCC"
                             }
                         }
                     }

                     MouseArea {
                         anchors.fill: parent
                         onClicked: {
                             mainSplit.setView(view, menuItem)
                         }
                     }

                     Image {
                         id: icon
                         height: 20
                         width: 20
                         anchors {
                             left: parent.left
                             verticalCenter: parent.verticalCenter
                             leftMargin: 3
                         }
                         MouseArea {
                             anchors.fill: parent
                             onClicked: {
                                 menuItem.closeApp()
                             }
                         }
                     }

                     Text {
                         id: label
                         anchors {
                             left: icon.right
                             verticalCenter: parent.verticalCenter
                             leftMargin: 3
                         }

                         color: "#0D0A01"
                         font.pixelSize: 12
                     }

                     Text {
                         id: secondary
                         anchors {
                             right: parent.right
                             rightMargin: 8
                             verticalCenter: parent.verticalCenter
                         }
                         color: "#AEADBE"
                         font.pixelSize: 12
                     }


                     function closeApp() {
                         if(!this.closable) { return; }

                         if(this.view.hasOwnProperty("onDestroy")) {
                             this.view.onDestroy.call(this.view)
                         }

                         this.view.destroy()
                         this.destroy()
                         gui.removePlugin(this.path)
                     }
                 }
             }

             function createMenuItem(icon, view, options) {
                 if(options === undefined) {
                     options = {};
                 }

                 var section;
                 switch(options.section) {
                     case "ethereum":
                     section = menuDefault;
                     break;
                     case "legacy":
                     section = menuLegacy;
                     break;
                     default:
                     section = menuApps;
                     break;
                 }

                 var comp = menuItemTemplate.createObject(section)

                 comp.view = view
                 comp.title = view.title
                 comp.icon = view.iconSource
                 comp.closable = options.close;

                 return comp
             }

             ColumnLayout {
                 id: menuColumn
                 y: 10
                 width: parent.width
                 anchors.left: parent.left
                 anchors.right: parent.right
                 spacing: 3

                 Text {
                     text: "ETHEREUM"
                     font.bold: true
                     anchors {
                         left: parent.left
                         leftMargin: 5
                     }
                     color: "#888888"
                 }

                 ColumnLayout {
                     id: menuDefault
                     spacing: 3
                     anchors {
                         left: parent.left
                         right: parent.right
                     }
                 }


                 Text {
                     text: "APPS"
                     font.bold: true
                     anchors {
                         left: parent.left
                         leftMargin: 5
                     }
                     color: "#888888"
                 }

                 ColumnLayout {
                     id: menuApps
                     spacing: 3
                     anchors {
                         left: parent.left
                         right: parent.right
                     }
                 }

                 Text {
                     text: "DEBUG"
                     font.bold: true
                     anchors {
                         left: parent.left
                         leftMargin: 5
                     }
                     color: "#888888"
                 }

                 ColumnLayout {
                     id: menuLegacy
                     spacing: 3
                     anchors {
                         left: parent.left
                         right: parent.right
                     }
                 }
             }
         }

         /*********************
          * Main view
          ********************/
          Rectangle {
              anchors.right: parent.right
              anchors.left: menu.right
              anchors.bottom: parent.bottom
              anchors.top: parent.top
              color: "#00000000"

              Rectangle {
                  id: urlPane
                  height: 40
                  color: "#00000000"
                  anchors {
                      left: parent.left
                      right: parent.right
                      leftMargin: 5
                      rightMargin: 5
                      top: parent.top
                      topMargin: 5
                  }
                  TextField {
                      id: url
                      objectName: "url"
                      placeholderText: "DApp URL"
                      anchors {
                          left: parent.left
                          right: parent.right
                          top: parent.top
                          topMargin: 5
                          rightMargin: 5
                          leftMargin: 5
                      }

                      Keys.onReturnPressed: {
                          addPlugin(this.text, {close: true, section: "apps"})
                      }
                  }

              }

              // Border
              Rectangle {
                  id: divider
                  anchors {
                      left: parent.left
                      right: parent.right
                      top: urlPane.bottom
                  }
                  z: -1
                  height: 1
                  color: "#CCCCCC"
              }

              Rectangle {
                  id: mainView
                  color: "#00000000"
                  anchors.right: parent.right
                  anchors.left: parent.left
                  anchors.bottom: parent.bottom
                  anchors.top: divider.bottom

                  function createView(component) {
                      var view = component.createObject(mainView)

                      return view;
                  }
              }
          }
      }


      /******************
       * Dialogs
       *****************/
       FileDialog {
           id: generalFileDialog
           property var callback;
           onAccepted: {
               var path = this.fileUrl.toString();
               callback.call(this, path);
           }

           function show(selectExisting, callback) {
               generalFileDialog.callback = callback;
               generalFileDialog.selectExisting = selectExisting;

               this.open();
           }
       }


       /******************
        * Wallet functions
        *****************/
        function importApp(path) {
            var ext = path.split('.').pop()
            if(ext == "html" || ext == "htm") {
                eth.openHtml(path)
            }else if(ext == "qml"){
                addPlugin(path, {close: true, section: "apps"})
            }
        }


        function setWalletValue(value) {
            walletValueLabel.text = value
        }

        function loadPlugin(name) {
            console.log("Loading plugin" + name)
            var view = mainView.addPlugin(name)
        }

        function setPeers(text) {
            peerLabel.text = text
        }

        function addPeer(peer) {
            // We could just append the whole peer object but it cries if you try to alter them
            peerModel.append({ip: peer.ip, port: peer.port, lastResponse:timeAgo(peer.lastSend), latency: peer.latency, version: peer.version})
        }

        function resetPeers(){
            peerModel.clear()
        }

        function timeAgo(unixTs){
            var lapsed = (Date.now() - new Date(unixTs*1000)) / 1000
            return  (lapsed + " seconds ago")
        }

        function convertToPretty(unixTs){
            var a = new Date(unixTs*1000);
            var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            var year = a.getFullYear();
            var month = months[a.getMonth()];
            var date = a.getDate();
            var hour = a.getHours();
            var min = a.getMinutes();
            var sec = a.getSeconds();
            var time = date+' '+month+' '+year+' '+hour+':'+min+':'+sec ;
            return time;
        }

        /**********************
         * Windows
         *********************/
         Window {
             id: peerWindow
             //flags: Qt.CustomizeWindowHint | Qt.Tool | Qt.WindowCloseButtonHint
             height: 200
             width: 700
             Rectangle {
                 anchors.fill: parent
                 property var peerModel: ListModel {
                     id: peerModel
                 }
                 TableView {
                     anchors.fill: parent
                     id: peerTable
                     model: peerModel
                     TableViewColumn{width: 100; role: "ip" ; title: "IP" }
                     TableViewColumn{width: 60; role: "port" ; title: "Port" }
                     TableViewColumn{width: 140; role: "lastResponse"; title: "Last event" }
                     TableViewColumn{width: 100; role: "latency"; title: "Latency" }
                     TableViewColumn{width: 260; role: "version" ; title: "Version" }
                 }
             }
         }

         Window {
             id: aboutWin
             visible: false
             title: "About"
             minimumWidth: 350
             maximumWidth: 350
             maximumHeight: 200
             minimumHeight: 200

             Image {
                 id: aboutIcon
                 height: 150
                 width: 150
                 fillMode: Image.PreserveAspectFit
                 smooth: true
                 source: "../facet.png"
                 x: 10
                 y: 10
             }

             Text {
                 anchors.left: aboutIcon.right
                 anchors.leftMargin: 10
                 anchors.top: parent.top
                 anchors.topMargin: 30
                 font.pointSize: 12
                 text: "<h2>Mist (0.6.5)</h2><h4>Amalthea</h4><br><h3>Development</h3>Jeffrey Wilcke<br>Viktor Tr??n<br><h3>Building</h3>Maran Hidskes"
             }
         }

         Window {
             id: txImportDialog
             minimumWidth: 270
             maximumWidth: 270
             maximumHeight: 50
             minimumHeight: 50
             TextField {
                 id: txImportField
                 width: 170
                 anchors.verticalCenter: parent.verticalCenter
                 anchors.left: parent.left
                 anchors.leftMargin: 10
                 onAccepted: {
                 }
             }
             Button {
                 anchors.left: txImportField.right
                 anchors.verticalCenter: parent.verticalCenter
                 anchors.leftMargin: 5
                 text: "Import"
                 onClicked: {
                     eth.importTx(txImportField.text)
                     txImportField.visible = false
                 }
             }
             Component.onCompleted: {
                 addrField.focus = true
             }
         }

         Window {
             id: addPeerWin
             visible: false
             minimumWidth: 300
             maximumWidth: 300
             maximumHeight: 50
             minimumHeight: 50
             title: "Connect to peer"

             ComboBox {
                 id: addrField
                 anchors.verticalCenter: parent.verticalCenter
                 anchors.left: parent.left
                 anchors.right: addPeerButton.left
                 anchors.leftMargin: 10
                 anchors.rightMargin: 10
                 onAccepted: {
                     eth.connectToPeer(addrField.currentText)
                     addPeerWin.visible = false
                 }

                 editable: true
                 model: ListModel { id: pastPeers }

                 Component.onCompleted: {
                     var ips = eth.pastPeers()
                     for(var i = 0; i < ips.length; i++) {
                         pastPeers.append({text: ips.get(i)})
                     }

                     pastPeers.insert(0, {text: "poc-6.ethdev.com:30303"})
                 }
             }

             Button {
                 id: addPeerButton
                 anchors.right: parent.right
                 anchors.verticalCenter: parent.verticalCenter
                 anchors.rightMargin: 10
                 text: "Add"
                 onClicked: {
                     eth.connectToPeer(addrField.currentText)
                     addPeerWin.visible = false
                 }
             }
             Component.onCompleted: {
                 addrField.focus = true
             }
         }
     }
