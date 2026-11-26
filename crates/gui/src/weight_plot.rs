use std::collections::BTreeMap;

use chrono::{Datelike, Days, Local, NaiveDate, TimeZone};
use eframe::egui::{self, Color32};
use egui_plot::{Legend, Line, LineStyle, Plot, PlotPoints, Points};

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
        .x_axis_formatter(move |tick, _| {
            date_label(
                tick.value,
                if grouping == GroupBy::Month {
                    "%b %Y"
                } else {
                    "%d %b"
                },
            )
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
                    .radius(3.5),
            );
            if points.len() > 1 {
                plot.line(
                    Line::new(name, PlotPoints::from(points))
                        .color(MEASURED)
                        .width(2.2),
                );
            }
            if let Some(forecast) = forecast {
                plot.line(
                    Line::new("30-day forecast", PlotPoints::from(forecast.to_vec()))
                        .color(FORECAST)
                        .width(2.0)
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

fn date_label(value: f64, format: &str) -> String {
    NaiveDate::from_num_days_from_ce_opt(value.round() as i32)
        .map_or_else(String::new, |date| date.format(format).to_string())
}

#[cfg(test)]
mod tests {
    use chrono::{Local, TimeZone};
    use xiaomi_s200::Weight;

    use super::{GroupBy, WeightEntry, grouped_points, projected_line};

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
