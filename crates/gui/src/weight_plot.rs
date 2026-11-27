use std::collections::BTreeMap;

use chrono::{Datelike, Days, Local, NaiveDate, TimeZone};
use eframe::egui::{self, Color32};
use egui_plot::{GridInput, GridMark, Legend, Line, LineStyle, Plot, PlotPoints, Points};

use super::history::WeightEntry;

const FORECAST_DAYS: f64 = 30.0;
const FORECAST_SAMPLES: usize = 30;
const MILLIS_PER_DAY: f64 = 86_400_000.0;
const MEASURED: Color32 = Color32::from_rgb(17, 102, 80);
const FORECAST: Color32 = Color32::from_rgb(166, 90, 31);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) enum GroupBy {
    #[default]
    Day,
    Week,
    Month,
}

impl GroupBy {
    fn label(self) -> &'static str {
        match self {
            Self::Day => "By day",
            Self::Week => "By week",
            Self::Month => "By month",
        }
    }

    fn series_name(self) -> &'static str {
        match self {
            Self::Day => "Recorded weight",
            Self::Week => "Weekly average",
            Self::Month => "Monthly average",
        }
    }

    fn bucket(self, date: NaiveDate) -> Option<NaiveDate> {
        match self {
            Self::Day => Some(date),
            Self::Week => {
                date.checked_sub_days(Days::new(date.weekday().num_days_from_monday().into()))
            }
            Self::Month => date.with_day(1),
        }
    }
}

pub(super) fn show(ui: &mut egui::Ui, entries: &[WeightEntry], grouping: &mut GroupBy) {
    ui.horizontal_wrapped(|ui| {
        ui.heading("Weight history");
        for option in [GroupBy::Day, GroupBy::Week, GroupBy::Month] {
            ui.selectable_value(grouping, option, option.label());
        }
    });
    let points = grouped_points(entries, *grouping);
    if points.is_empty() {
        ui.label("Your first settled reading will appear here.");
        return;
    }

    let forecast = projected_line(entries, &points);
    let grouping = *grouping;
    Plot::new(("weight-history", grouping))
        .height(ui.available_height().max(180.0) - 24.0)
        .legend(Legend::default())
        .y_axis_label("kg")
        .x_grid_spacer(calendar_grid)
        .x_axis_formatter(|tick, visible_days| {
            let format = if visible_days.end() - visible_days.start() >= 365.0 {
                "%d %b %Y"
            } else {
                "%d %b"
            };
            date_label(tick.value, format)
        })
        .label_formatter(|name, point| {
            format!(
                "{name}\n{}\n{:.2} kg",
                date_label(point.x, "%d %b %Y"),
                point.y
            )
        })
        .show(ui, |plot| {
            let name = grouping.series_name();
            plot.points(
                Points::new(name, PlotPoints::from(points.clone()))
                    .color(MEASURED)
                    .radius(3.5_f32),
            );
            if points.len() > 1 {
                plot.line(
                    Line::new(name, PlotPoints::from(points))
                        .color(MEASURED)
                        .width(2.2_f32),
                );
            }
            if let Some(forecast) = forecast {
                plot.line(
                    Line::new("30-day forecast", PlotPoints::from(forecast.to_vec()))
                        .color(FORECAST)
                        .width(2.0_f32)
                        .style(LineStyle::Dashed { length: 7.0 }),
                );
            }
        });
    if entries.len() < 3 {
        ui.label("The 30-day forecast appears after three recorded weights.");
    }
}

#[derive(Default)]
struct Bucket {
    total_kg: f64,
    count: u32,
}

fn grouped_points(entries: &[WeightEntry], grouping: GroupBy) -> Vec<[f64; 2]> {
    let mut buckets = BTreeMap::<NaiveDate, (NaiveDate, Bucket)>::new();
    for entry in entries {
        let Some(date) = Local
            .timestamp_millis_opt(entry.measured_at_ms)
            .single()
            .map(|time| time.date_naive())
        else {
            continue;
        };
        let Some(key) = grouping.bucket(date) else {
            continue;
        };
        let (last_date, bucket) = buckets
            .entry(key)
            .or_insert_with(|| (date, Bucket::default()));
        *last_date = (*last_date).max(date);
        bucket.total_kg += kilograms(entry);
        bucket.count += 1;
    }
    buckets
        .into_values()
        .map(|(date, bucket)| {
            [
                f64::from(date.num_days_from_ce()),
                bucket.total_kg / f64::from(bucket.count),
            ]
        })
        .collect()
}

fn projected_line(entries: &[WeightEntry], points: &[[f64; 2]]) -> Option<[[f64; 2]; 2]> {
    let recent = &entries[entries.len().saturating_sub(FORECAST_SAMPLES)..];
    if recent.len() < 3 {
        return None;
    }
    let anchor = *points.last()?;
    let origin = recent[0].measured_at_ms as f64;
    let days = |entry: &WeightEntry| (entry.measured_at_ms as f64 - origin) / MILLIS_PER_DAY;
    let sample_count = recent.len() as f64;
    let average_day = recent.iter().map(days).sum::<f64>() / sample_count;
    let average_weight = recent.iter().map(kilograms).sum::<f64>() / sample_count;
    let covariance = recent
        .iter()
        .map(|entry| (days(entry) - average_day) * (kilograms(entry) - average_weight))
        .sum::<f64>();
    let variance = recent
        .iter()
        .map(|entry| (days(entry) - average_day).powi(2))
        .sum::<f64>();
    let predicted = anchor[1] + FORECAST_DAYS * (covariance / variance);
    (predicted.is_finite() && predicted > 0.0)
        .then_some([anchor, [anchor[0] + FORECAST_DAYS, predicted]])
}

fn kilograms(entry: &WeightEntry) -> f64 {
    f64::from(entry.weight.hundredths_of_kg()) / 100.0
}

fn calendar_grid(input: GridInput) -> Vec<GridMark> {
    // Reserve about 96 screen points per date label using egui_plot's default 8-point grid unit.
    let step_days = (input.base_step_size * 12.0).ceil().max(1.0);
    if !step_days.is_finite() {
        return Vec::new();
    }
    let (min, max) = input.bounds;
    let min = min.max(f64::from(NaiveDate::MIN.num_days_from_ce()));
    let max = max.min(f64::from(NaiveDate::MAX.num_days_from_ce()));
    let first = (min / step_days).ceil() as i64;
    let last = (max / step_days).floor() as i64;
    (first..=last)
        .map(|index| GridMark {
            value: index as f64 * step_days,
            step_size: step_days,
        })
        .collect()
}

fn date_label(value: f64, format: &str) -> String {
    NaiveDate::from_num_days_from_ce_opt(value.round() as i32)
        .map_or_else(String::new, |date| date.format(format).to_string())
}

#[cfg(test)]
mod tests {
    use chrono::{Local, TimeZone};
    use eframe::egui::{self, Shape};
    use egui_plot::{GridInput, GridMark};
    use xiaomi_s200::Weight;

    use super::{GroupBy, WeightEntry, calendar_grid, grouped_points, projected_line, show};

    #[test]
    fn paints_one_date_label_for_one_weigh_in_in_every_group() {
        let entry = WeightEntry {
            measured_at_ms: Local
                .with_ymd_and_hms(2026, 11, 26, 12, 0, 0)
                .single()
                .unwrap()
                .timestamp_millis(),
            weight: Weight::from_hundredths_of_kg(8440),
        };
        for mut grouping in [GroupBy::Day, GroupBy::Week, GroupBy::Month] {
            let context = egui::Context::default();
            let output = context.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(780.0, 640.0),
                    )),
                    ..Default::default()
                },
                |context| {
                    egui::CentralPanel::default().show(context, |ui| {
                        show(ui, &[entry], &mut grouping);
                    });
                },
            );
            let labels = output.shapes.iter().filter(
                |shape| matches!(&shape.shape, Shape::Text(text) if text.galley.text() == "26 Nov"),
            );
            assert_eq!(labels.count(), 1, "{grouping:?}");
        }
    }

    #[test]
    fn dates_stay_on_whole_days_at_different_zoom_levels() {
        let zoomed_in = calendar_grid(GridInput {
            bounds: (100.8, 101.2),
            base_step_size: 0.01,
        });
        assert_eq!(
            zoomed_in,
            [GridMark {
                value: 101.0,
                step_size: 1.0,
            }]
        );

        let zoomed_out = calendar_grid(GridInput {
            bounds: (100.8, 200.2),
            base_step_size: 1.68,
        });
        assert_eq!(
            zoomed_out.iter().map(|mark| mark.value).collect::<Vec<_>>(),
            [105.0, 126.0, 147.0, 168.0, 189.0]
        );
    }

    #[test]
    fn groups_by_calendar_period_and_forecasts_past_the_last_point() {
        let entry = |day, weight| WeightEntry {
            measured_at_ms: Local
                .with_ymd_and_hms(2026, 11, day, 12, 0, 0)
                .single()
                .unwrap()
                .timestamp_millis(),
            weight: Weight::from_hundredths_of_kg(weight),
        };
        let entries = [entry(23, 7200), entry(24, 7190), entry(25, 7180)];
        let daily = grouped_points(&entries, GroupBy::Day);
        let weekly = grouped_points(&entries, GroupBy::Week);
        let monthly = grouped_points(&entries, GroupBy::Month);
        assert_eq!(daily.len(), 3);
        assert_eq!(weekly.len(), 1);
        assert_eq!(weekly, monthly);
        assert!((weekly[0][1] - 71.9).abs() < 0.001);
        assert!(projected_line(&entries[..2], &daily).is_none());
        let line = projected_line(&entries, &daily).unwrap();
        assert_eq!(line[0], daily[2]);
        assert_eq!(line[1][0] - line[0][0], 30.0);
        assert!((line[1][1] - 68.8).abs() < 0.001);
    }
}
