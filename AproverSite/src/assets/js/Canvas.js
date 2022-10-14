import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";


import PrincipalLabel from "./PrincipalLabel";
import JailHousePrincipal from "./JailHousePrincipal.js";
import EndPrincipal from "./EndPrincipal.js";
import TimeLinePrincipal from "./TimeLinePrincipal.js";
import SelectionMenuPolicy from "./SelectionMenuPolicy.js";
import KnowledgeMark from "./KnowledgeMark.js";

var textFigure = null;
var canvas = null;
document.addEventListener("DOMContentLoaded", function () {

    // create the canvas for the user interaction
    //
    canvas = new draw2d.Canvas("gfx_holder");
    canvas.installEditPolicy(new draw2d.policy.canvas.CoronaDecorationPolicy());
    // create and add two nodes which contains Ports (In and OUT)
    //


    var MyInputPortLocator = draw2d.layout.locator.PortLocator.extend({
        init: function () {
            this._super();
        },
        relocate: function (index, figure) {
            this.applyConsiderRotation(figure, figure.getParent().getWidth() / 2, 0);
        }
    });


    var MyOutputPortLocator = draw2d.layout.locator.PortLocator.extend({
        init: function () {
            this._super();
        },
        relocate: function (index, figure) {
            var p = figure.getParent();

            this.applyConsiderRotation(figure, p.getWidth() / 2, p.getHeight());
        }
    });

    let alice = new PrincipalLabel();
    alice.setActor("Alice");
    alice.createPort("hybrid", new MyOutputPortLocator());

    let endAlice = new EndPrincipal();
    endAlice.createPort("hybrid", new MyInputPortLocator());

    let jail = new JailHousePrincipal();
    jail.setHeight(canvas.getHeight());
    jail.setWidth(canvas.getWidth() / 4);

    canvas.add(alice, canvas.getWidth() / 8 - 60, 20);
    canvas.add(endAlice, canvas.getWidth() / 8 - 75, canvas.getHeight() - 30);


    var aliceTime = new TimeLinePrincipal({
        source: alice.getPorts().first(),
        target: endAlice.getPorts().first()
    });

    canvas.add(aliceTime);

    let aliceTimeLen=aliceTime.getLength();
    let aliceTimeUpX=aliceTime.getStartX(); 
    let aliceTimeUpY=aliceTime.getStartY(); 

    let aliceX = alice.getAbsoluteX();
    let aliceY = alice.getAbsoluteY();
    let endAliceX = endAlice.getAbsoluteX();
    let endAliceY = endAlice.getAbsoluteY();
    //let aliceLowCenterX=canvas.getWidth()/8;
    //let aliceLowCenterY=aliceY+alice.getHeight();
    //let endLineY=jail.getHeight()-20;

    canvas.add(jail, 0, 0);

    jail.assignFigure(alice);
    jail.assignFigure(endAlice);

    alice.installEditPolicy(new draw2d.policy.figure.RegionEditPolicy(aliceX, aliceY, alice.getWidth(), alice.getHeight()));
    endAlice.installEditPolicy(new draw2d.policy.figure.RegionEditPolicy(endAliceX, endAliceY, endAlice.getWidth(), endAlice.getHeight()));

    //let line = new draw2d.shape.basic.Line({ startX: aliceLowCenterX, startY: aliceLowCenterY, endX: aliceLowCenterX, endY:endLineY });
    //canvas.add(line);
    //jail.assignFigure(line);

    let nTrip=1;
    let vbusA1 = new KnowledgeMark($.extend({nTrip:nTrip}));

   
    canvas.add(vbusA1, aliceTimeUpX-5, aliceTimeUpY+20);
    vbusA1.installEditPolicy(new draw2d.policy.figure.AntSelectionFeedbackPolicy());
    vbusA1.installEditPolicy(new SelectionMenuPolicy());
    
    jail.assignFigure(vbusA1);
    vbusA1.toFront();

    nTrip=3
    let vbusA2 = new KnowledgeMark($.extend({nTrip:nTrip}));

   
    canvas.add(vbusA2, aliceTimeUpX-5, aliceTimeUpY+65);
    vbusA2.installEditPolicy(new draw2d.policy.figure.AntSelectionFeedbackPolicy());
    vbusA2.installEditPolicy(new SelectionMenuPolicy());
    
    jail.assignFigure(vbusA2);
    vbusA2.toFront();

    /////////////////////////////////////////////////////////////////////
    // BOB
    /////////////////////////////////////////////////////////////////////
    nTrip=2
    let bob = new PrincipalLabel();
    bob.setActor("Bob");
   
    bob.createPort("hybrid", new MyOutputPortLocator());

    let endBob = new EndPrincipal();
    endBob.createPort("hybrid", new MyInputPortLocator());

    let jailBob = new JailHousePrincipal();
    jailBob.setHeight(canvas.getHeight());
    jailBob.setWidth(canvas.getWidth() / 4);

    canvas.add(bob, (canvas.getWidth() / 4) +(canvas.getWidth() / 8) - 60, 20);
    canvas.add(endBob, (canvas.getWidth() / 4) +(canvas.getWidth() / 8) - 75, canvas.getHeight() - 30);
    bob.setActorColor("#38761d");

    var bobTime = new TimeLinePrincipal({
        source: bob.getPorts().first(),
        target: endBob.getPorts().first()
    });

    canvas.add(bobTime);

    let bobTimeLen=bobTime.getLength();
    let bobTimeUpX=bobTime.getStartX(); 
    let bobTimeUpY=bobTime.getStartY(); 

    let bobX = bob.getAbsoluteX();
    let bobY = bob.getAbsoluteY();
    let endBobX = endBob.getAbsoluteX();
    let endBobY = endBob.getAbsoluteY();
    //let bobLowCenterX=canvas.getWidth()/8;
    //let aliceLowCenterY=aliceY+alice.getHeight();
    //let endLineY=jail.getHeight()-20;

    canvas.add(jailBob, canvas.getWidth() / 4, 0);

    jailBob.assignFigure(bob);
    jailBob.assignFigure(endBob);

    bob.installEditPolicy(new draw2d.policy.figure.RegionEditPolicy(bobX, bobY, bob.getWidth(), bob.getHeight()));
    endBob.installEditPolicy(new draw2d.policy.figure.RegionEditPolicy(endBobX, endBobY, endBob.getWidth(), endBob.getHeight()));

    //let line = new draw2d.shape.basic.Line({ startX: aliceLowCenterX, startY: aliceLowCenterY, endX: aliceLowCenterX, endY:endLineY });
    //canvas.add(line);
    //jail.assignFigure(line);

    
    let vbusB1 = new KnowledgeMark($.extend({nTrip:nTrip}));
    vbusB1.setBackgroundColor('#739F60');
    canvas.add(vbusB1, bobTimeUpX-5, bobTimeUpY+35);
    vbusB1.installEditPolicy(new draw2d.policy.figure.AntSelectionFeedbackPolicy());
    vbusB1.installEditPolicy(new SelectionMenuPolicy());
    
    jailBob.assignFigure(vbusB1);
    vbusB1.toFront();

});