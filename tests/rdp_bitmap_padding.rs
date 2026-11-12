//! Регрессия на обработку bitmap-обновлений с «шириной больше прямоугольника».
//!
//! xrdp дополняет строку bitmap'а до кратности 4 пикселям и включает это
//! дополнение в `width` заголовка TS_BITMAP_DATA: например, для прямоугольника
//! 7x15 приходит `width = 8`. Строки нужно читать по заявленной ширине и
//! обрезать до прямоугольника назначения — иначе каждый ряд сдвигается на
//! 1–2 пикселя и изображение «расползается» диагональными полосами.

use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::bitmap::{BitmapData, BitmapUpdateData, Compression};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_session::fast_path::{Processor, ProcessorBuilder};
use ironrdp_session::image::DecodedImage;

fn processor() -> Processor {
    ProcessorBuilder {
        io_channel_id: 0,
        user_channel_id: 0,
        share_id: 0,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        bulk_decompressor: None,
    }
    .build()
}

#[test]
fn padded_declared_width_is_repacked_to_rectangle() {
    let mut image = DecodedImage::new(PixelFormat::BgrA32, 16, 4);
    let mut processor = processor();

    // Три строки по 5 пикселей, дополненные до 8 (3 пикселя padding).
    // Данные bottom-up: первая строка в потоке — нижняя строка прямоугольника.
    // Синий канал кодирует номер строки потока, зелёный — номер столбца.
    let mut data = Vec::new();
    for row in 0..3u8 {
        for col in 0..5u8 {
            data.extend_from_slice(&[row * 10, col * 10, 0, 0xFF]);
        }
        // Дополнение не должно попасть в изображение.
        data.extend_from_slice(&[0xAA; 12]);
    }

    let rectangle = InclusiveRectangle {
        left: 2,
        top: 1,
        right: 6,  // ширина 5
        bottom: 3, // высота 3
    };
    let update = BitmapUpdateData {
        rectangles: vec![BitmapData {
            rectangle,
            width: 8, // заявленная ширина: 5 + 3 пикселя дополнения
            height: 3,
            bits_per_pixel: 32,
            compression_flags: Compression::empty(),
            compressed_data_header: None,
            bitmap_data: &data,
        }],
    };

    processor
        .process_bitmap_update(&mut image, update)
        .expect("bitmap update");

    let pixels = image.data();
    let stride = usize::from(image.width()) * 4;
    for row in 0..3usize {
        // Первая строка потока — нижняя (bottom-up).
        let y = 3 - row;
        for col in 0..5usize {
            let offset = y * stride + (2 + col) * 4;
            assert_eq!(
                pixels[offset],
                row as u8 * 10,
                "B: строка потока {row}, столбец {col}"
            );
            assert_eq!(
                pixels[offset + 1],
                col as u8 * 10,
                "G: строка потока {row}, столбец {col}"
            );
            assert_eq!(pixels[offset + 3], 0xFF, "альфа непрозрачная");
        }
        // Справа от прямоугольника пиксели не тронуты.
        let offset = y * stride + 7 * 4;
        assert_eq!(&pixels[offset..offset + 4], &[0, 0, 0, 0]);
    }
    // Строка выше прямоугольника не тронута.
    assert!(pixels[0..stride].iter().all(|byte| *byte == 0));
}
