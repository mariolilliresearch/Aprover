import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default draw2d.shape.basic.Rectangle.extend({
    NAME: "PrincipalLabel",

    init: function (attr) {
        this._super($.extend({ bgColor: "#0b5394", height: "60", width: "120" }), attr);

        // Create any Draw2D figure as decoration for the connection

        //


        //this.label.installEditor(new draw2d.ui.LabelInplaceEditor());
    },

    setActor: function (name) {
        this.label = new draw2d.shape.basic.Label({ text: name, color: "#0b5394", fontColor: "#0d0d0d", fontSize: "25" });

        // add the new decoration to the connection with a position locator.
        //
        this.add(this.label, new draw2d.layout.locator.CenterLocator(this));
        return this;
    },

    setActorColor: function (col) {
        this.setBackgroundColor(col);
        this.getChildren().first().setColor(col);
        return this;
    },

    setKnowledgeTab: function () {

    }

});