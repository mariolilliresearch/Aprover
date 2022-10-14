import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default draw2d.Connection.extend({

  NAME:"MyConnection",
    
    init:function(attr, setter, getter)
    {
      this._super($.extend({
        stroke: 3,
        outlineStroke: 1,
        outlineColor: "#303030",
        color: "#036016"
      },attr),
      setter,
      getter);

      this.setRouter(new draw2d.layout.connection.SplineConnectionRouter());

      this.on("removed", (element, event) => {
          if(element.getTarget().NAME !== "draw2d.OutputPort"){
            element.getTarget().setValue(null);
          }else{
            element.getSource().setValue(null);
          }
            
        });
    },


});