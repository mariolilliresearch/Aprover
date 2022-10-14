import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";


export default Parser=Class.extend({

    NAME: "Parser",

    init: function () {

    },

    setMessage: function (message) {
        document.getElementById("toolbar_message_preview").innerHTML = message;
    }
});