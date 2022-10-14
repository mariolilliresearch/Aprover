import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import InputPortKnowledgeMark from "./InputPortKnowledgeMark.js";
import OutputPortKnowledgeMark from "./OutputPortKnowledgeMark.js";


export default draw2d.shape.basic.Rectangle.extend({
    NAME: 'KnowledgeMark',

    init: function (attr, setter,getter) {
        this._super($.extend({ bgColor: "#5486B4", height: "30", width: "10" }), 
        $.extend({
            nTrip : this.setnTrip
        },setter),
        $.extend({
            nTrip : this.getnTrip
        },getter),attr);
        
       

    },

    setnTrip: function(n){

        if (n == 1) {
            var outputLocatorInit= new draw2d.layout.locator.OutputPortLocator();
            this.createPort("hybrid", outputLocatorInit);
           
        } else if(n%2==0){
            var inputLocator = new InputPortKnowledgeMark();
                this.createPort("hybrid", inputLocator);
                this.createPort("hybrid", inputLocator);
        } else{
            var outputLocator = new OutputPortKnowledgeMark();
                this.createPort("hybrid", outputLocator);
                this.createPort("hybrid", outputLocator);
        }
        return this;

    }


})