import * as bootstrap from 'bootstrap';

import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";


window.$ = jQuery;
window.jQuery = jQuery;



    $(".dropdown-menu li a").click(function () {

        $(this).parents(".btn-group").find('.selection').text($(this).text());
        $(this).parents(".btn-group").find('.selection').val($(this).text());

    });
