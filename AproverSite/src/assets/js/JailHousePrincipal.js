import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default draw2d.shape.composite.Jailhouse.extend({

    NAME: "JailHousePrincipal",

    init: function (attr, setter, getter) {
        this._super($.extend({ stroke: 1, color: '#ececec', bgColor: null, width: 270, height: 184 }, attr), setter, getter);
        var port;
    },
    createShapeElement: function () {
        var shape = this._super();
        this.originalWidth = 270;
        this.originalHeight = 184;
        return shape;
    }

});