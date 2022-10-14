import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import CommandDelete from './CommandDelete.js';
import FlowPortsFeedbackPolicy from "./FlowPortsFeedbackPolicy.js";

export default Message=draw2d.shape.layout.VerticalLayout.extend({

    NAME: "Message",

    init: function (attr) {
        this._super($.extend({ bgColor: "#dbddde", color: "#d7d7d7", stroke: 1, radius: 3 }, attr));

        this.parser = null;


        this.classLabel = new draw2d.shape.basic.Label({
            text: "ClassName",
            bold: true,
            stroke: 1,
            fontColor: "#FBFCFC",
            bgColor: "#16679a",
            color: "#11527B",
            radius: this.getRadius(),
            padding: 10,
            resizeable: true,
            editor: new draw2d.ui.LabelInplaceEditor()
        });


        this.add(this.classLabel);
    },



    /**
    * @method
    * Add an entity to the db shape
    * 
    * @param {String} txt the label to show
    * @param {Number} [optionalIndex] index where to insert the entity
    */
    addEntity: function (container, txt) {
        var label = new draw2d.shape.basic.Label({
            text: txt,
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });

        //        label.installEditor(new draw2d.ui.LabelEditor());
        var input = label.createPort("input");
        input.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        input.installEditPolicy(new FlowPortsFeedbackPolicy());
        input.setName("input_" + label.id);
        input.setColor("#04773b");
        input.setBackgroundColor("#04773b");
        input.setMaxFanOut(1);


        var _table = this;

        label.on("contextmenu", function (emitter, event) {
            $.contextMenu({
                selector: 'body',
                events:
                {
                    hide: function () { $.contextMenu('destroy'); }
                },
                callback: $.proxy(function (key, options) {
                    switch (key) {
                        case "rename":
                            setTimeout(function () {
                                emitter.onDoubleClick();
                            }, 10);
                            break;
                        case "new":
                            setTimeout(function () {
                                _table.addEntity(container, "_new_").onDoubleClick();
                                _table.onPortValueChanged();
                            }, 10);
                            break;
                        case "delete":
                            // with undo/redo support
                            var cmd = new CommandDelete(emitter);
                            emitter.getCanvas().getCommandStack().execute(cmd);
                            _table.onPortValueChanged();
                        default:
                            break;
                    }

                }, this),
                x: event.x,
                y: event.y,
                items:
                {
                    "rename": { name: "Rename" },
                    "new": { name: "New Entity" },
                    "sep1": "---------",
                    "delete": { name: "Delete" }
                }
            });
        });


        container.addRow(label);
        this.updateCachedPort(input);


        input.on("connect", (element, event) => {
            var connections = input.getConnections();
            console.log(input);
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });


        return label;
    },
    /**
    * @method
    * Add an entity to the db shape
    * 
    * @param {String} txt the label to show
    * @param {Number} [optionalIndex] index where to insert the entity
    */
    addInOut: function (parser) {
        this.parser = parser;

        var label = new draw2d.shape.basic.Label({
            text: "Field 1",
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });
        var label1 = new draw2d.shape.basic.Label({
            text: "Field 2",
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });
        //        label.installEditor(new draw2d.ui.LabelEditor());
        var input = label.createPort("input");
        input.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        input.installEditPolicy(new FlowPortsFeedbackPolicy());
        input.setName("input_" + label.id);
        input.setColor("#04773b");
        input.setBackgroundColor("#04773b");
        input.setMaxFanOut(1);

        var input1 = label1.createPort("input");
        input1.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        input1.installEditPolicy(new FlowPortsFeedbackPolicy());
        input1.setName("input_" + label1.id);
        input1.setColor("#04773b");
        input1.setBackgroundColor("#04773b");
        input1.setMaxFanOut(1);

        var _table = this;
        label1.on("contextmenu", function (emitter, event) {
            $.contextMenu({
                selector: 'body',
                events:
                {
                    hide: function () { $.contextMenu('destroy'); }
                },
                callback: $.proxy(function (key, options) {
                    switch (key) {
                        case "rename":
                            setTimeout(function () {
                                emitter.onDoubleClick();
                            }, 10);
                            break;
                        case "new":
                            setTimeout(function () {
                                _table.addEntity(container, "_new_").onDoubleClick();
                                _table.onPortValueChanged();
                            }, 10);
                            break;
                        case "delete":
                            // with undo/redo support
                            //var layout = emitter.getParent();
                            var cmd = new CommandDelete(emitter);
                            emitter.getCanvas().getCommandStack().execute(cmd);
                            _table.onPortValueChanged();
                        default:
                            break;
                    }

                }, this),
                x: event.x,
                y: event.y,
                items:
                {
                    "rename": { name: "Rename" },
                    "new": { name: "New Entity" },
                    "sep1": "---------",
                    "delete": { name: "Delete" }
                }
            });
        });

        label.on("contextmenu", function (emitter, event) {
            $.contextMenu({
                selector: 'body',
                events:
                {
                    hide: function () { $.contextMenu('destroy'); }
                },
                callback: $.proxy(function (key, options) {
                    switch (key) {
                        case "rename":
                            setTimeout(function () {
                                emitter.onDoubleClick();
                            }, 10);
                            break;
                        case "new":
                            setTimeout(function () {
                                _table.addEntity(container, "_new_").onDoubleClick();
                                _table.onPortValueChanged();
                            }, 10);
                            break;
                        default:
                            break;
                    }

                }, this),
                x: event.x,
                y: event.y,
                items:
                {
                    "rename": { name: "Rename" },
                    "new": { name: "New Entity" }
                }
            });
        });

        let container = new draw2d.shape.layout.TableLayout({
            bgColor: null,
            color: null,
            radius: this.getRadius(),
            resizeable: true,
            padding: { top: 5 }
        });

        container.addRow(label);
        container.addRow(label1);
        this.add(container);

        input.on("connect", (element, event) => {
            var connections = input.getConnections();
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });

        input1.on("connect", (element, event) => {
            var connections = input1.getConnections();
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });




        return container;
    },

    /**
     * @method
     * Remove the entity with the given index from the DB table shape.<br>
     * This method removes the entity without care of existing connections. Use
     * a draw2d.command.CommandDelete command if you want to delete the connections to this entity too
     * 
     * @param {Number} index the index of the entity to remove
     */
    removeEntity: function (index) {
        this.remove(this.children.get(index + 1).figure);
    },

    /**
     * @method
     * Returns the entity figure with the given index
     * 
     * @param {Number} index the index of the entity to return
     */
    getEntity: function (index) {
        return this.children.get(index + 1).figure;
    },


    /**
     * @method
     * Set the name of the DB table. Visually it is the header of the shape
     * 
     * @param name
     */
    setName: function (name) {
        this.classLabel.setText(name);

        return this;
    },


    /**
     * @method 
     * Return an objects with all important attributes for XML or JSON serialization
     * 
     * @returns {Object}
     */
    getPersistentAttributes: function () {
        var memento = this._super();

        memento.name = this.classLabel.getText();
        memento.entities = [];
        this.children.each(function (i, e) {

            if (i > 0) { // skip the header of the figure
                memento.entities.push({
                    text: e.figure.getText(),
                    id: e.figure.id
                });
            }
        });

        return memento;
    },

    /**
     * @method 
     * Read all attributes from the serialized properties and transfer them into the shape.
     *
     * @param {Object} memento
     * @return
     */
    setPersistentAttributes: function (memento) {
        this._super(memento);

        this.setName(memento.name);

        if (typeof memento.entities !== "undefined") {
            $.each(memento.entities, $.proxy(function (i, e) {
                var entity = this.addEntity(e.text);
                entity.id = e.id;
                entity.getInputPort(0).setName("input_" + e.id);
                entity.getOutputPort(0).setName("output_" + e.id);
            }, this));
        }

        return this;
    },



    getInputPorts: function () {
        var inports = new draw2d.util.ArrayList();
        var inport1 = this.getChildren().get(1).getChildren().get(0).getPorts().get(0);
        inports.add(inport1);
        var size = this.getChildren().get(1).getChildren().getSize();
        for (let i = 1; i < size; i++) {
            inports.add(this.getChildren().get(1).getChildren().get(i).getPorts().get(0));
        }

        return inports
    },
    /**
    * @method
    * Called if the value of any port has been changed
    *
    * @param {draw2d.Port} relatedPort
    * @template
    */
    onPortValueChanged: function (relatedPort) {
        var data = [];
        this.getInputPorts().each(function (i, port) {
            data.push(port.getValue());
        });

        var temp = "";
        for (let i = 0; i < data.length - 1; i++) {

            temp = temp + data[i] + ', ';

        }
        temp = temp + data[data.length - 1];
        //this.getOutputPorts().get(0).setValue('{' + data[1] + '}<sub>' + data[0] + '<sub>')


        this.parser.setMessage(temp);
    }

});