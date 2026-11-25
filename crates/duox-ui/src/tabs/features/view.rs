//! Layout of the tab: command groups on top, the result view below.

use super::{Action, Message, State};
use crate::shared::Shared;
use crate::ui::{theme, widgets};
use iced::widget::{button, column, container, pick_list, row, scrollable, text, Row};
use iced::{Element, Length};

/// A command button; without a connection it is shown disabled.
fn act<'a>(connected: bool, label: &str, action: Action) -> Element<'a, Message> {
    if connected {
        widgets::secondary(label, Message::Do(action)).into()
    } else {
        button(text(label.to_string())).padding([5, 14]).into()
    }
}

fn buttons<'a>(items: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    Row::with_children(items).spacing(theme::SPACE_SM).wrap().vertical_spacing(theme::SPACE_SM).into()
}

impl State {
    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let on = shared.is_connected();
        let a = |label: &str, action| act(on, label, action);

        let iso = widgets::group(
            "ISO/IEC 7816-4",
            column![
                widgets::hint(
                    "Plain commands, only while no authentication is active; refused in an application with a \
                     TransactionMAC file."
                ),
                buttons(vec![
                    a("Select DF name...", Action::SelectDf),
                    a("Select file ID...", Action::SelectEf),
                    a("Select MF", Action::SelectMf),
                    a("GetChallenge...", Action::GetChallenge),
                ]),
                buttons(vec![
                    a("ReadBinary...", Action::ReadBinary),
                    a("UpdateBinary...", Action::UpdateBinary),
                    a("ReadRecord...", Action::ReadRecord),
                    a("AppendRecord...", Action::AppendRecord),
                ]),
                buttons(vec![a("Fast UID...", Action::FastUid)]),
                widgets::hint("Fast UID selects the application by DF name and decrypts the UID in the FCI with the AppUIDENCKey."),
            ]
            .spacing(theme::SPACE_SM),
        );

        let two = widgets::group(
            "Two applications selected at once",
            column![
                buttons(vec![
                    a("Select both...", Action::SelectTwo),
                    a("File settings...", Action::SecondSettings),
                    a("Read file...", Action::SecondRead),
                    a("Write file...", Action::SecondWrite),
                ]),
                widgets::hint(
                    "Keys and files of the second application are addressed with bit 7 set: authenticate with key \
                     81 for its key 1; file 01 is sent as 81. The Card tab keeps showing the first application."
                ),
            ]
            .spacing(theme::SPACE_SM),
        );

        let prox = widgets::group(
            "Proximity check",
            column![
                buttons(vec![a("Run...", Action::Proximity)]),
                widgets::hint(
                    "A PC/SC reader cannot time the exchange to the published response time: a pass proves the \
                     cryptographic part, not the absence of a relay."
                ),
            ]
            .spacing(theme::SPACE_SM),
        );

        let gpio = widgets::group(
            "GPIO",
            buttons(vec![
                a("Configure...", Action::GpioConfig),
                a("ManageGPIO...", Action::GpioManage),
                a("ReadGPIO...", Action::GpioRead),
            ]),
        );

        let issuer: Element<'_, Message> = if self.cas.is_empty() {
            widgets::hint("No CA in the store. Create one on the CAs & certificates tab.").into()
        } else {
            pick_list(self.cas.clone(), self.selected_ca().cloned(), Message::CaPicked)
                .placeholder("Choose the issuer")
                .width(Length::Fill)
                .into()
        };
        let ev = widgets::group(
            "EV charging (VDE-AR-E 2532-100)",
            column![
                row![text("Certificate issuer"), issuer].spacing(theme::SPACE_SM).align_y(iced::Alignment::Center),
                buttons(vec![
                    a("Provision application...", Action::EvProvision),
                    a("Read + verify certificate", Action::EvRead),
                    a("Challenge card", Action::EvChallenge),
                ]),
                buttons(vec![
                    a("Read data", Action::EvData),
                    a("Write data...", Action::EvWrite),
                    a("Lock data...", Action::EvLock),
                ]),
                widgets::hint(
                    "Every EV command selects the application by DF name first, which ends any authentication."
                ),
            ]
            .spacing(theme::SPACE_SM),
        );

        let left = column![iso, two].spacing(theme::SPACE_MD).width(Length::FillPortion(1));
        let right = column![prox, gpio, ev].spacing(theme::SPACE_MD).width(Length::FillPortion(1));
        let controls = scrollable(
            row![left, right].spacing(theme::SPACE_MD).width(Length::Fill),
        )
        .height(Length::FillPortion(5));

        let result = column![
            row![
                widgets::section("Result"),
                widgets::secondary("Copy", Message::Copy),
                widgets::secondary("Clear", Message::Clear),
            ]
            .spacing(theme::SPACE_SM)
            .align_y(iced::Alignment::Center),
            container(self.out.view().map(Message::View)).height(Length::Fill),
        ]
        .spacing(theme::SPACE_XS)
        .height(Length::FillPortion(4));

        column![controls, result].spacing(theme::SPACE_MD).padding([theme::SPACE_MD, 0.0]).into()
    }
}
