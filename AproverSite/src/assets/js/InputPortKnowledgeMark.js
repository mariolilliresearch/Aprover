import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
export default draw2d.layout.locator.PortLocator.extend({
    NAME : "InputPortKnowledgeMark",
     
  
    init: function()
    {
      this._super();
    },    
   
   /**
    * @method
    * Controls the location of an {@link draw2d.Figure}
    *
    * @param {Number} index port index of the figure
    * @param {draw2d.Figure} figure the figure to control
    * 
    * @template
    **/
    relocate: function(index, figure)
   {
        var node = figure.getParent();
        
        var dividerFactor = 1;
        var thisNAME = this.NAME;
        var portIndex =1;
        node.getPorts().each(function(i,p){
        	portIndex = (p===figure)?dividerFactor:portIndex;
        	dividerFactor += p.getLocator().NAME === thisNAME?1:0;
        });
    
        if(portIndex==1){
          this.applyConsiderRotation( figure, 0, 0);
        }else{
          this.applyConsiderRotation( figure, 0, (node.getHeight()));
        }
       
    }
    
});