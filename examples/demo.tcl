#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

lappend auto_path [file dirname [file dirname [file normalize [info script]]]]
package require tcaptcha 1.0.0
if {[llength $argv] > 3} {error "usage: tclsh demo.tcl ?output.png? ?length? ?letters?"}
set filename [expr {[llength $argv] ? [lindex $argv 0] : "captcha.png"}]
set length [expr {[llength $argv] > 1 ? [lindex $argv 1] : 6}]
set letters [expr {[llength $argv] > 2 ? [lindex $argv 2] : true}]
set mac [::tink::register_keyset [::tink::mac::create_keyset HMAC_SHA256]]
try {
    set challenge [::tcaptcha::create -mac $mac -context standalone-demo -length $length -letters $letters]
    set output [open $filename {WRONLY CREAT EXCL}]
    try {
        fconfigure $output -translation binary
        puts -nonewline $output [dict get $challenge png]
    } finally {close $output}
    puts "Open [file normalize $filename] to view the challenge."
    puts -nonewline "Enter its $length [expr {$letters ? {characters} : {digits}}]: "
    flush stdout
    if {[gets stdin answer] < 0} {error "no answer supplied"}
    set valid [::tcaptcha::verify $mac standalone-demo [dict get $challenge state] $answer]
    puts [expr {$valid ? "Correct." : "Incorrect or expired."}]
    # A real host must consume the saved state atomically, including on failure.
    unset challenge
} finally {::tink::unregister_keyset $mac}
