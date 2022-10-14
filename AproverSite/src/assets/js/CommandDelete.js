import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";


export default CommandDelete=draw2d.command.Command.extend({

    NAME: "CommandDelete",

    /**
     * @constructor
     * Create a delete command for the given figure.
     * 
     * @param {draw2d.Figure} figure
     */
    init: function( figure)
    {
       this._super();
       
       this.parent   = figure.getParent();
       this.figure   = figure;
       this.canvas   = figure.getCanvas();
       this.connections = null;
       this.removedParentEntry = null; // can be null if the figure didn't have any parent shape assigned
       this.indexOfChild = -1;
    },


    /**
     * @method
     * Returns [true] if the command can be execute and the execution of the
     * command modifies the model. e.g.: a CommandMove with [startX,startX] == [endX,endY] should
     * return false. The execution of this Command doesn't modify the model.
     *
     * @return {Boolean} return try if the command modify the model or make any relevant changes
     **/
    canExecute: function()
    {
        // we can only delete the figure if its part of the canvas.
        return this.figure.getCanvas()!==null;
    },

    /**
     * @method
     * Execute the command the first time
     * 
     **/
    execute: function()
    {
       this.redo();
    },
    
    /**
     * @method
     * Undo the command
     *
     **/
    undo: function()
    {
        if(this.parent!==null){
            console.log(this.removedParentEntry[0][0])
            this.parent.addIndexRow(this.removedParentEntry[0][0],this.indexOfChild);
            this.canvas.setCurrentSelection(this.parent.parent);
        }
       
        
        if(this.figure instanceof draw2d.Connection){
           this.figure.reconnect();
        }
    
         
        for (var i = 0; i < this.connections.getSize(); ++i){
           this.canvas.add(this.connections.get(i));
           this.connections.get(i).reconnect();
        }
    },

    /**
     * @method
     * 
     * Redo the command after the user has undo this command
     *
     **/
    redo: function()
    {
       this.canvas.setCurrentSelection(null);
        
       // Collect all connections that are bounded to the figure to delete. This connections
       // must be deleted too.
       //
       if(this.connections===null)
       {
          if(this.figure instanceof draw2d.shape.node.Node){
              this.connections = this.figure.getConnections();
          }
          else{
              this.connections = new draw2d.util.ArrayList();
          }
       }
       
   // already done in the canvas.remove(..) method
   //    if(this.figure instanceof draw2d.Connection){
   //        this.figure.disconnect();
   //    }


       // remove all connections
       //
       for (var i = 0; i < this.connections.getSize(); ++i){
           this.canvas.remove(this.connections.get(i));
       }

       // remove this figure from the parent 
       //
       if(this.parent!==null){
           // determine the index of the child before remove
          this.indexOfChild = this.parent.getIndex(this.figure);
          this.removedParentEntry= this.parent.removeRow(this.indexOfChild);
       }
      
    }
});