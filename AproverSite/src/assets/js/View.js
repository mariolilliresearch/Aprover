import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import Parser from "./Parser.js";
import AsymmetricEncryption from "./AsymmetricEncryption.js";
import AsymmetricPrivKey from "./AsymmetricPrivKey.js"
import LabelRight from "./LabelRight.js";
import SymmetricEncryption from "./SymmetricEncryption.js";
import Signature from "./Signature.js";
import MAC from "./MAC.js";
import Hash from "./Hash.js";
import Group from "./Group.js";
import Nounce from "./Nounce.js";
import IDCertificate from "./IDCertificate.js";
import BitStringData from "./BitStringData.js";
import SymmetricKey from "./SymmetricKey.js";
import AsymmetricPubKey from "./AsymmetricPubKey.js";
import Message from "./Message.js";


export default  draw2d.Canvas.extend({

    NAME:'View',
  

    init: function (id, parser) {
        this._super(id, 2000, 2000);

        this.setScrollArea("#" + id);

        this.parser = parser;

        this.message = 0;
        this.nounce = 0;
        this.timestamp = 0;
        this.idcert = 0;
        this.bitstring = 0;
        this.symkey = 0;
        this.asymprivkey = 0;
        this.asympubkey = 0;

    },


    /**
     * @method
     * Called if the user drop the droppedDomNode onto the canvas.<br>
     * <br>
     * Draw2D use the jQuery draggable/droppable lib. Please inspect
     * http://jqueryui.com/demos/droppable/ for further information.
     * 
     * @param {HTMLElement} droppedDomNode The dropped DOM element.
     * @param {Number} x the x coordinate of the drop
     * @param {Number} y the y coordinate of the drop
     * @param {Boolean} shiftKey true if the shift key has been pressed during this event
     * @param {Boolean} ctrlKey true if the ctrl key has been pressed during the event
     * @private
     **/
    onDrop: function (droppedDomNode, x, y, shiftKey, ctrlKey) {
        var type = $(droppedDomNode).data("shape");
        if ((this.message < 1 || type !== "Message") && (this.nounce < 1 || type !== "Nounce") && (this.timestamp < 1 || type !== "Timestamp")
            && (this.idcert < 1 || type !== "IDCertificate") && (this.bitstring < 1 || type !== "BitStringData")
            && (this.symkey < 1 || type !== "SymmetricKey") && (this.asympubkey < 1 || type !== "AsymmetricPubKey")
            && (this.asymprivkey < 1 || type !== "AsymmetricPrivKey")) {
            
           
            var figure = eval("new " + type + "();");
            if (type === "Message") {
                figure.addInOut(this.parser);

            } else {
                figure.addInOut();
            }




            switch (type) {
                case "SymmetricEncryption": figure.setName("AES"); break;
                case "AsymmetricEncryption": figure.setName("RSA"); break;
                case "Signature": figure.setName("DSA"); break;
                case "MAC": figure.setName("MAC"); break;
                case "Hash": figure.setName("SHA3"); break;
                case "Message": figure.setName("Message Name"); this.message = this.message + 1; break;
                case "Group": figure.setName("Group"); break;
                case "Nounce": figure.setName("Nounce"); this.nounce = this.nounce + 1; break;
                case "IDCertificate": figure.setName("ID Certificate"); this.idcert = this.idcert + 1; break;
                case "BitStringData": figure.setName("BitString"); this.bitstring = this.bitstring + 1; break;
                case "Timestamp": figure.setName("Timestamp"); this.timestamp = this.timestamp + 1; break;
                case "SymmetricKey": figure.setName("Symmetric Key"); this.symkey = this.symkey + 1; break;
                case "AsymmetricPubKey": figure.setName("Asymmetric Public Key"); this.asympubkey = this.asympubkey + 1; break;
                case "AsymmetricPrivKey": figure.setName("Asymmetric Private Key"); this.asymprivkey = this.asymprivkey + 1; break;
                default: console.log("error 404: Type not Found");
            }

            // create a command for the undo/redo support
            var command = new draw2d.command.CommandAdd(this, figure, x, y);
            this.getCommandStack().execute(command);
        }
    },

    removeInstance: function (name) {
        switch (name) {
            case "Message": this.message = this.message - 1; break;
            case "Nounce": this.nounce = this.nounce - 1; break;
            case "IDCertificate": this.idcert = this.idcert - 1; break;
            case "BitStringData": this.bitstring = this.bitstring - 1; break;
            case "Timestamp": this.timestamp = this.timestamp - 1; break;
            case "SymmetricKey": this.symkey = this.symkey - 1; break;
            case "AsymmetricPubKey": this.asympubkey = this.asympubkey - 1; break;
            case "AsymmetricPrivKey": this.asymprivkey = this.asymprivkey - 1; break;
            default: console.log("It's been deleted " + name );
        }

    }
});

