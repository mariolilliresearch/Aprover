import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default draw2d.Connection.extend({
  
    /** required for JSON serialize/deserialize. **/
    NAME: "TimeLinePrincipal",
  
    init:function(attr)
    {
      this._super(attr);

      this.setRouter(new draw2d.layout.connection.InteractiveManhattanConnectionRouter());
      this.setOutlineStroke(0);
      this.setOutlineColor("#191919");
      this.setStroke(1);
      this.setColor('#191919');
      //this.setRadius(20);
    }
   

});