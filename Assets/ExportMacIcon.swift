import AppKit
import SwiftUI
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 3,
      let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: CommandLine.arguments[1]) as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(source, 0, nil),
      image.width == image.height else { fatalError("Expected a square PNG and an output path") }
let side = image.width
guard let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpace(name: CGColorSpace.sRGB)!,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { fatalError("No bitmap context") }
let bounds = CGRect(x: 0, y: 0, width: side, height: side)
let tile = bounds.insetBy(dx: CGFloat(side) * 0.09, dy: CGFloat(side) * 0.09)
let outline = RoundedRectangle(cornerRadius: tile.width * 0.22, style: .continuous).path(in: tile).cgPath
context.addPath(outline)
context.clip()
context.draw(image, in: bounds)
guard let output = context.makeImage(),
      let destination = CGImageDestinationCreateWithURL(URL(fileURLWithPath: CommandLine.arguments[2]) as CFURL,
                                                        UTType.png.identifier as CFString, 1, nil) else { fatalError("PNG export failed") }
CGImageDestinationAddImage(destination, output, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("PNG export failed") }
print("Exported \(side) × \(side) PNG using a native continuous-corner outline and transparent margins")
