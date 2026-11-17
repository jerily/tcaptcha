#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

package require Tcl 8.6 9
package require tclgd 1.4.0
package require tink 20240704.0.2
package require thashlib 0.1.0
namespace eval ::tcaptcha {
    variable alphabet 23456789ABCDEFGHJKLMNPQRSTUVWXYZ
    variable digits 0123456789
    # Five-bit rows, drawn with GD. No system fonts or external assets required.
    variable glyphs {
        0 {14 17 19 21 25 17 14} 1 {4 12 4 4 4 4 14}
        2 {14 17 1 2 4 8 31} 3 {30 1 1 14 1 1 30}
        4 {2 6 10 18 31 2 2} 5 {31 16 16 30 1 1 30}
        6 {14 16 16 30 17 17 14} 7 {31 1 2 4 8 8 8}
        8 {14 17 17 14 17 17 14} 9 {14 17 17 15 1 1 14}
        A {14 17 17 31 17 17 17} B {30 17 17 30 17 17 30}
        C {14 17 16 16 16 17 14} D {30 17 17 17 17 17 30}
        E {31 16 16 30 16 16 31} F {31 16 16 30 16 16 16}
        G {14 17 16 23 17 17 15} H {17 17 17 31 17 17 17}
        J {7 2 2 2 18 18 12} K {17 18 20 24 20 18 17}
        L {16 16 16 16 16 16 31} M {17 27 21 21 17 17 17}
        N {17 25 25 21 19 19 17} P {30 17 17 30 16 16 16}
        Q {14 17 17 17 21 18 13} R {30 17 17 30 20 18 17}
        S {15 16 16 14 1 1 30} T {31 4 4 4 4 4 4}
        U {17 17 17 17 17 17 14} V {17 17 17 17 17 10 4}
        W {17 17 17 21 21 21 10} X {17 17 10 4 10 17 17}
        Y {17 17 10 4 4 4 4} Z {31 1 2 4 8 16 31}
    }
}
# Obtain cryptographic random bytes from thashlib.
proc ::tcaptcha::random_bytes {count} {::thashlib::random_bytes $count}
# Rejection sampling avoids bias for arbitrary bounds.
proc ::tcaptcha::random_int {bound} {
    if {![string is wideinteger -strict $bound] || $bound < 1 || $bound > 4294967296} {error "random bound must be 1..4294967296"}
    set limit [expr {4294967296 - 4294967296 % $bound}]
    while {1} {
        binary scan [random_bytes 4] Iu value
        if {$value < $limit} {return [expr {$value % $bound}]}
    }
}
# Build the domain-separated CAPTCHA authentication input.
proc ::tcaptcha::message {context id expires answer} {
    encoding convertto utf-8 [list tcaptcha 1 $context $id $expires $answer]
}
# Return PNG bytes and an authenticated state dictionary for server-side storage.
# Never send state to the browser. The caller must consume it atomically on use.
proc ::tcaptcha::create {args} {
    variable alphabet
    variable digits
    set options [dict create -mac {} -context {} -ttl 300 -length 6 -letters true]
    if {[llength $args] % 2} {error "expected option/value pairs"}
    foreach {key value} $args {
        if {![dict exists $options $key]} {error "unknown option: $key"}
        dict set options $key $value
    }
    foreach key {-mac -context} {
        if {[dict get $options $key] eq {}} {error "$key is required"}
    }
    set ttl [dict get $options -ttl]
    if {![string is integer -strict $ttl] || $ttl < 1 || $ttl > 3600} {error "-ttl must be 1..3600 seconds"}
    set length [dict get $options -length]
    if {![string is integer -strict $length] || $length < 4 || $length > 12} {error "-length must be 4..12 characters"}
    set letters [dict get $options -letters]
    if {![string is boolean -strict $letters]} {error "-letters must be a boolean"}
    set characters [expr {$letters ? $alphabet : $digits}]
    set answer {}
    for {set i 0} {$i < $length} {incr i} {append answer [string index $characters [random_int [string length $characters]]]}
    set id [binary encode hex [random_bytes 16]]
    set expires [expr {[clock seconds] + $ttl}]
    set tag [binary encode hex [::tink::mac::compute [dict get $options -mac] \
        [message [dict get $options -context] $id $expires $answer]]]
    dict create png [image $answer] state [dict create id $id expires $expires tag $tag]
}
# Verify only; persistence, one-time consumption and attempt limits belong to
# the host so the same challenge works across workers and process restarts.
proc ::tcaptcha::verify {mac context state answer} {
    if {[string length $answer] > 64 || [catch {dict size $state}]} {return 0}
    foreach key {id expires tag} {if {![dict exists $state $key]} {return 0}}
    set id [dict get $state id]
    set expires [dict get $state expires]
    set tag [dict get $state tag]
    set answer [string toupper [string trim $answer]]
    if {![regexp {^[0-9a-f]{32}$} $id] || ![string is wideinteger -strict $expires] ||
        $expires <= [clock seconds] || ![regexp {^[0-9a-f]{64,128}$} $tag] ||
        [string length $tag] % 2 || ![regexp {^[0-9A-HJ-NP-Z]{4,12}$} $answer]} {return 0}
    ::tink::mac::verify $mac [binary decode hex $tag] [message $context $id $expires $answer]
}
# Render 4..12 supported characters with per-letter shifts, a gentle wave, and
# background noise. This is a basic visual challenge, not a bot-proof guarantee.
proc ::tcaptcha::image {text} {
    variable glyphs
    if {![regexp {^[0-9A-HJ-NP-Z]{4,12}$} $text]} {error "image text must be 4..12 uppercase CAPTCHA characters"}
    set width [expr {24 + 36 * [string length $text]}]
    set right [expr {$width - 1}]
    set im [GD create_truecolor #auto $width 80]
    try {
        $im filled_rectangle 0 0 $right 79 0xf3f5f7
        for {set i 0} {$i < $width * 5 / 12} {incr i} {
            $im filled_ellipse [random_int $width] [random_int 80] 2 2 0xb5c1ce
        }
        for {set i 0} {$i < 5} {incr i} {
            $im line 0 [random_int 80] $right [random_int 80] 0xc4ced9
        }
        set index 0
        foreach character [split $text {}] {
            set left [expr {16 + $index * 36 + [random_int 5]}]
            set top [expr {20 + [random_int 13]}]
            set phase [expr {[random_int 100] / 16.0}]
            set color [$im allocate_color [expr {25 + [random_int 45]}] [expr {35 + [random_int 45]}] [expr {50 + [random_int 45]}]]
            set row 0
            foreach bits [dict get $glyphs $character] {
                for {set col 0} {$col < 5} {incr col} {
                    if {!($bits & (1 << (4 - $col)))} {continue}
                    set x [expr {$left + $col * 4 + int(3 * sin($phase + $row * 0.65))}]
                    set y [expr {$top + $row * 4}]
                    $im filled_rectangle $x $y [expr {$x + 3}] [expr {$y + 3}] $color
                }
                incr row
            }
            incr index
        }
        return [$im png_data 6]
    } finally {rename $im {}}
}
package provide tcaptcha 1.0.0
