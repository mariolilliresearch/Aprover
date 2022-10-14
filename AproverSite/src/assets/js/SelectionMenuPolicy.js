import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import Application from "./Application.js";
import MyConnection from "./MyConnection.js";
var url = require("../../messageBuilder.html")

export default draw2d.policy.figure.SelectionPolicy.extend({
	NAME: "SelectionMenuPolicy",

	init: function (attr, setter, getter) {
		this.overlay = null; // div DOM node

		this._super(attr, setter, getter);
	},

	/**
	 * @method
	 *
	 * @template
	 * @param {draw2d.Canvas} canvas the related canvas
	 * @param {draw2d.Figure} figure the selected figure
	 * @param {boolean} isPrimarySelection
	 */
	onSelect: function (canvas, figure, isPrimarySelection) {
		this._super(canvas, figure, isPrimarySelection);

		if (this.overlay === null) {
			this.overlay = $("<div class='overlayMenu'>&#x2295;</div>");
			$(".seqdiagram").append(this.overlay);
			var messageComposer;
			this.overlay.on("click", function () {

				/* if (typeof (winRef) == 'undefined' || winRef.closed) {
					//create new
					//var url = "./messageBuilder.html";
					//winRef = window.open('', 'winPop', 'sampleListOfOptions');
					if (winRef == null || winRef.document.location.href != url) { */
						winRef = window.open(url,'_blank').focus();
						
					
				/* 	}
				}
				else {
					//give it focus (in case it got burried)
					winRef.focus();
				} */

				//var command = new draw2d.command.CommandDelete(figure);
				//canvas.getCommandStack().execute(command);
			})
		}
		this.posOverlay(figure);
	},


	/**
	 * @method
	 *
	 * @param {draw2d.Canvas} canvas the related canvas
	 * @param {draw2d.Figure} figure the unselected figure
	 */
	onUnselect: function (canvas, figure) {
		this._super(canvas, figure);

		this.overlay.remove();
		this.overlay = null;
	},

	onDrag: function (canvas, figure) {
		this._super(canvas, figure);
		this.posOverlay(figure);
	},

	posOverlay: function (figure) {
		this.overlay.css({
			"top": figure.getAbsoluteY() - 20,
			"left": figure.getAbsoluteX() + figure.getWidth() + 20
		});
	}
});