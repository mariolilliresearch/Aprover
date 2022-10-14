import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default Group=draw2d.shape.layout.VerticalLayout.extend({

    NAME: "Group",

    init: function (attr) {
        this._super($.extend({ bgColor: "#dbddde", color: "#d7d7d7", stroke: 1, radius: 3, resizeable: true, }, attr));


        this.classLabel = new draw2d.shape.basic.Label({
            text: "ClassName",
            bold: true,
            stroke: 1,
            fontColor: "#FBFCFC",
            bgColor: "#0899ba",
            color: "#067A94",
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
                            var cmd = new CommandRemoveRow(emitter);
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

        console.log(this.getPorts());

        return label;
    },
    /**
     * @method
     * Add an entity to the db shape
     * 
     * @param {String} txt the label to show
     * @param {Number} [optionalIndex] index where to insert the entity
     */
    addInOut: function () {
        var labelKnowledge1 = new draw2d.shape.basic.Label({
            text: "Knowledge 1",
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });

        var labelKnowledge2 = new draw2d.shape.basic.Label({
            text: "Knowledge 2",
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });

        var labelTag = new LabelRight({
            text: "Group",
            stroke: 0,
            radius: 0,
            bgColor: null,
            padding: { left: 10, top: 3, right: 10, bottom: 5 },
            fontColor: "#4a4a4a",
            resizeable: true,
            editor: new draw2d.ui.LabelEditor()
        });

        var input1 = labelKnowledge1.createPort("input");
        input1.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        input1.installEditPolicy(new draw2d.policy.port.FlowPortsFeedbackPolicy());
        input1.setName("input_" + labelKnowledge1.id);
        input1.setColor("#04773b");
        input1.setBackgroundColor("#04773b");
        input1.setMaxFanOut(1);


        var input2 = labelKnowledge2.createPort("input");
        input2.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        input2.installEditPolicy(new draw2d.policy.port.FlowPortsFeedbackPolicy());
        input2.setName("input_" + labelKnowledge2.id);
        input2.setColor("#04773b");
        input2.setBackgroundColor("#04773b");
        input2.setMaxFanOut(1);

        var output = labelTag.createPort("output");
        output.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        output.installEditPolicy(new draw2d.policy.port.FlowPortsFeedbackPolicy());
        output.setName("output_" + labelTag.id);
        output.setColor("#04773b");
        output.setBackgroundColor("#04773b");


        let container = new draw2d.shape.layout.TableLayout({
            bgColor: null,
            color: null,
            radius: this.getRadius(),
            resizeable: true,
            padding: { top: 5 }
        });

        container.addRow(labelKnowledge1, labelTag);
        //container.setCellAlign(0, 1, "right");
        container.addRow(labelKnowledge2);


        var _table = this;

        labelKnowledge2.on("contextmenu", function (emitter, event) {
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

        this.add(container);


        input1.on("connect", (element, event) => {
            var connections = input1.getConnections();
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });

        input2.on("connect", (element, event) => {
            var connections = input2.getConnections();
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });

        output.on("change:value", (element, event) => {
            var connections = output.getConnections();
            connections.each((i, conn) => {
                var targetPort = conn.getTarget();
                targetPort.setValue(conn.getSource().getValue());
            });
        });

        return container;
    },

    /**
     * @method
     * Add an entity to the db shape
     * 
     * @param {String} txt the label to show
     * @param {Number} [optionalIndex] index where to insert the entity
     */
    addEntityIn: function (txt) {
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
        input.installEditPolicy(new draw2d.policy.port.FlowPortsFeedbackPolicy());
        //var output = label.createPort("output");

        input.setName("input_" + label.id);

        return label;
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
     * Add an entity to the db shape
     * 
     * @param {String} txt the label to show
     * @param {Number} [optionalIndex] index where to insert the entity
     */
    addEntityOut: function (txt) {
        var label = new LabelRight({
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
        //var input = label.createPort("input");
        var output = label.createPort("output");
        output.uninstallEditPolicy(new draw2d.policy.port.IntrusivePortsFeedbackPolicy());
        output.installEditPolicy(new draw2d.policy.port.FlowPortsFeedbackPolicy());
        //input.setName("input_" + label.id);
        output.setName("output_" + label.id);

        return label;
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
        let container = new draw2d.shape.layout.TableLayout({
            bgColor: null,
            color: null,
            radius: this.getRadius(),
            resizeable: true
        });
        if ((typeof memento.entitiesInput !== "undefined") && (typeof memento.entitiesOutput !== "undefined")) {
            var lenOut = (memento.entitiesOutput).length

            $.each(memento.entitiesInput, $.proxy(function (i, e) {
                var entityin = this.addEntityIn(e.text);
                entityin.id = e.id;
                entityin.getInputPort(0).setName("input_" + e.id);
                //entityin.setLabelAligment(PositionConstants.LEFT);
                if (i == 0) {
                    container.attr({
                        padding: { top: 5 }
                    });
                }
                if (i < lenOut) {
                    var entityout = this.addEntityOut((memento.entitiesOutput)[i].text);
                    entityout.id = (memento.entitiesOutput)[i].id;
                    entityout.getOutputPort(0).setName("output_" + (memento.entitiesOutput)[i].id);
                    //entityout.text-anchor = "";
                    container.addRow(entityin, entityout);
                    container.setCellAlign(i, 1, "right");
                } else {
                    container.addRow(entityin);
                }



            }, this));
        }
        this.add(container);
        return this;
    },

    getOutputPorts: function () {
        var outport = this.getChildren().get(1).getChildren().get(1).getPorts().get(0);
        //console.log(this.getChildren().get(1).getChildren().get(1).getPorts().get(0));
        return outport;
    },

    getInputPorts: function () {
        var inports = new draw2d.util.ArrayList();
        var inport1 = this.getChildren().get(1).getChildren().get(0).getPorts().get(0);
        var inport2 = this.getChildren().get(1).getChildren().get(2).getPorts().get(0);
        inports.add(inport1);
        inports.add(inport2);
        var size = this.getChildren().get(1).getChildren().getSize();
        for (let i = 3; i < size; i++) {
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

        this.getOutputPorts().setValue(temp);
        console.log(this.getOutputPorts().getValue());
    }


});