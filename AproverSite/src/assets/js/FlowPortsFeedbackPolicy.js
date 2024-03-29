import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import { Tweenable } from "shifty";

export default FlowPortsFeedbackPolicy=draw2d.policy.port.PortFeedbackPolicy.extend({

    NAME: "FlowPortsFeedbackPolicy",

    /**
     * @constructor 
     */
    init: function (attr, setter, getter) {
        this._super(attr, setter, getter);
        this.connectionLine = null;
        this.tweenable = null;
    },

    /**
     * @method
     * Called by the framework if the related shape has init a drag&drop
     * operation
     * 
     * @param {draw2d.Canvas} canvas The host canvas
     * @param {draw2d.Figure} figure The related figure
     * @param {Number} x the x-coordinate of the mouse up event
     * @param {Number} y the y-coordinate of the mouse up event
     * @param {Boolean} shiftKey true if the shift key has been pressed during this event
     * @param {Boolean} ctrlKey true if the ctrl key has been pressed during the event
     */
    onDragStart: function (canvas, figure, x, y, shiftKey, ctrlKey) {
        var start = 0;
        var allPorts = canvas.getAllPorts().clone();
        allPorts.each(function (i, element) {
            if (typeof element.__beforeInflate === "undefined") {
                element.__beforeInflate = element.getWidth();
            }
            start = element.__beforeInflate;
        });


        // animate the resize of the ports
        //

        allPorts.grep(function (p) {
            //console.log(p.parent.getText() + " " + figure.parent.getText() + " " + p.parent.parent.parent.NAME + " " + figure.parent.parent.parent.NAME + " " + (p.NAME != figure.NAME && p.parent.parent.parent !== figure.parent.parent.parent));
            return (p.parent.NAME != figure.parent.NAME && p.parent.parent.parent !== figure.parent.parent.parent) || (p instanceof draw2d.HybridPort) || (figure instanceof draw2d.HybridPort);
        });

        this.tweenable = new Tweenable();
        this.tweenable.tween({
            from: { 'size': start / 2 },
            to: { 'size': start },
            duration: 200,
            easing: "easeOutSine",
            step: function (params) {
                allPorts.each(function (i, element) {
                    // IMPORTANT shortcut to avoid rendering errors!!
                    // performance shortcut to avoid a lot of events and recalculate/routing of all related connections
                    // for each setDimension call. Additional the connection is following a port during Drag&Drop operation
                    element.shape.attr({ rx: params.size, ry: params.size });
                    element.width = element.height = params.size * 2;
                    //element.setDimension(params.size, params.size);
                });
            }
        });

        this.connectionLine = new draw2d.shape.basic.Line();
        this.connectionLine.setCanvas(canvas);
        this.connectionLine.getShapeElement();
        this.connectionLine.setDashArray("- ");
        this.connectionLine.setColor("#30c48a");

        this.onDrag(canvas, figure);

        return true;
    },


    /**
     * @method
     * Called by the framework during drag a figure.
     * 
     * @param {draw2d.Canvas} canvas The host canvas
     * @param {draw2d.Figure} figure The related figure
     * @template
     */
    onDrag: function (canvas, figure) {
        var x1 = figure.ox + figure.getParent().getAbsoluteX();
        var y1 = figure.oy + figure.getParent().getAbsoluteY();

        this.connectionLine.setStartPoint(x1, y1);
        this.connectionLine.setEndPoint(figure.getAbsoluteX(), figure.getAbsoluteY());
    },

    /**
     * @method
     * Called by the framework if the drag drop operation ends.
     * 
     * @param {draw2d.Canvas} canvas The host canvas
     * @param {draw2d.Figure} figure The related figure
     * @template
     */
    onDragEnd: function (canvas, figure, x, y, shiftKey, ctrlKey) {
        if (this.tweenable) {
            this.tweenable.stop(true);
            this.tweenable.dispose();
            this.tweenable = null;
        }
        canvas.getAllPorts().each(function (i, element) {
            // IMPORTANT shortcut to avoid rendering errors!!
            // performance shortcut to avoid a lot of events and recalculate/routing of all related connections
            // for each setDimension call. Additional the connection is following a port during Drag&Drop operation
            element.shape.attr({ rx: element.__beforeInflate / 2, ry: element.__beforeInflate / 2 });
            element.width = element.height = element.__beforeInflate;
            delete element.__beforeInflate;
            //element.setDimension(element.__beforeInflate, element.__beforeInflate);
        });
        this.connectionLine.setCanvas(null);
        this.connectionLine = null;
    },

    onHoverEnter: function (canvas, draggedFigure, hoverFiger) {
        this.connectionLine.setGlow(true);
        hoverFiger.setGlow(true);
    },

    onHoverLeave: function (canvas, draggedFigure, hoverFiger) {
        hoverFiger.setGlow(false);
        if (this.connectionLine === null) {
            debugger;
        }
        this.connectionLine.setGlow(false);
    }


});