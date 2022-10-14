
import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

import View from "./View.js";
import Toolbar from "./Toolbar.js";
import Parser from "./Parser.js";
import MyConnection from "./MyConnection.js";
import DragConnectionCreatePolicy2 from "./DragConnectionCreatePolicy2.js";





export default Application =Class.extend(
    {
        NAME: "Application",

        init: function () {
            this.parser = new Parser();
            
            this.view = new View("canvas", this.parser);
            this.view.installEditPolicy(new DragConnectionCreatePolicy2({
                createConnection: function () {
                    return new MyConnection();
                }
            }));
            this.toolbar = new Toolbar("toolbar", "submit", this.view);

        }


    });
