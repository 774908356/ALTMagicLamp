/**
 * DO NOT EDIT
 *
 * This file was automatically generated by
 *   https://github.com/Polymer/gen-typescript-declarations
 *
 * To modify these typings, edit the source file(s):
 *   animations/hero-animation.html
 */

/// <reference path="../../polymer/types/polymer.d.ts" />
/// <reference path="../neon-shared-element-animation-behavior.d.ts" />

/**
 * `<hero-animation>` is a shared element animation that scales and transform an element such that it
 * appears to be shared between two pages. Use this in `<neon-animated-pages>`. The source page
 * should use this animation in an 'exit' animation and set the `fromPage` configuration property to
 * itself, and the destination page should use this animation in an `entry` animation and set the
 * `toPage` configuration property to itself. They should also define the hero elements in the
 * `sharedElements` property (not a configuration property, see
 * `Polymer.NeonSharedElementAnimatableBehavior`).
 *
 * Configuration:
 * ```
 * {
 *   name: 'hero-animation',
 *   id: <shared-element-id>,
 *   timing: <animation-timing>,
 *   toPage: <node>, /* define for the destination page *\/
 *   fromPage: <node>, /* define for the source page *\/
 * }
 * ```
 */
interface HeroAnimationElement extends Polymer.Element, Polymer.NeonSharedElementAnimationBehavior {
  complete(config: any): any;
  configure(config: any): any;
}

interface HTMLElementTagNameMap {
  "hero-animation": HeroAnimationElement;
}
