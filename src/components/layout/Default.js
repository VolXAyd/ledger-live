// @flow

import { remote } from 'electron'
import React, { Fragment, Component } from 'react'
import { compose } from 'redux'
import styled from 'styled-components'
import { Route, withRouter } from 'react-router'
import { translate } from 'react-i18next'
import { SYNC_PENDING_INTERVAL } from 'config/constants'

import type { Location } from 'react-router'

import * as modals from 'components/modals'
import Box from 'components/base/Box'
import GrowScroll from 'components/base/GrowScroll'
import Track from 'analytics/Track'

import AccountPage from 'components/AccountPage'
import DashboardPage from 'components/DashboardPage'
import ManagerPage from 'components/ManagerPage'
import ExchangePage from 'components/ExchangePage'
import SettingsPage from 'components/SettingsPage'
import KeyboardContent from 'components/KeyboardContent'
import PerfIndicator from 'components/PerfIndicator'
import LibcoreBusyIndicator from 'components/LibcoreBusyIndicator'
import DeviceBusyIndicator from 'components/DeviceBusyIndicator'
import TriggerAppReady from 'components/TriggerAppReady'
import ExportLogsBtn from 'components/ExportLogsBtn'
import OnboardingOrElse from 'components/OnboardingOrElse'
import AppRegionDrag from 'components/AppRegionDrag'
import IsUnlocked from 'components/IsUnlocked'
import SideBar from 'components/MainSideBar'
import TopBar from 'components/TopBar'
import SyncBackground from 'components/SyncBackground'
import SyncContinuouslyPendingOperations from '../SyncContinouslyPendingOperations'

const Main = styled(GrowScroll).attrs({
  px: 6,
})`
  outline: none;
  padding-top: ${p => p.theme.sizes.topBarHeight + p.theme.space[7]}px;
`

type Props = {
  location: Location,
  i18n: {
    reloadResources: Function,
  },
}

class Default extends Component<Props> {
  componentDidMount() {
    window.addEventListener('keydown', this.kbShortcut)
  }

  componentDidUpdate(prevProps) {
    if (this.props.location !== prevProps.location) {
      const canScroll =
        this._scrollContainer &&
        this._scrollContainer._scrollbar &&
        this._scrollContainer._scrollbar.scrollTo
      if (canScroll) {
        // $FlowFixMe already checked this._scrollContainer
        this._scrollContainer._scrollbar.scrollTo(0, 0)
      }
    }
  }

  componentWillUnmount() {
    window.removeEventListener('keydown', this.kbShortcut) // Prevents adding multiple listeners when hot reloading
  }

  kbShortcut = event => {
    if (event.ctrlKey && event.key === 'l') {
      this.props.i18n.reloadResources()
    } else if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
      remote.getCurrentWindow().webContents.reload()
    }
  }

  _scrollContainer = null

  render() {
    return (
      <Fragment>
        <TriggerAppReady />
        {process.platform === 'darwin' && <AppRegionDrag />}
        <ExportLogsBtn hookToShortcut />
        <Track mandatory onMount event="App Starts" />

        <OnboardingOrElse>
          <IsUnlocked>
            {Object.entries(modals).map(([name, ModalComponent]: [string, any]) => (
              <ModalComponent key={name} />
            ))}

            <SyncContinuouslyPendingOperations priority={20} interval={SYNC_PENDING_INTERVAL} />
            <SyncBackground />

            <div id="sticky-back-to-top-root" />

            <Box grow horizontal bg="white">
              <SideBar />

              <Box shrink grow bg="lightGrey" color="grey" overflow="hidden" relative>
                <TopBar />
                <Main innerRef={n => (this._scrollContainer = n)} tabIndex={-1}>
                  <Route path="/" exact component={DashboardPage} />
                  <Route path="/settings" component={SettingsPage} />
                  <Route path="/manager" component={ManagerPage} />
                  <Route path="/exchange" component={ExchangePage} />
                  <Route path="/account/:id" component={AccountPage} />
                </Main>
              </Box>
            </Box>

            <LibcoreBusyIndicator />
            <DeviceBusyIndicator />
            <KeyboardContent sequence="BJBJBJ">
              <PerfIndicator />
            </KeyboardContent>
          </IsUnlocked>
        </OnboardingOrElse>
      </Fragment>
    )
  }
}

export default compose(
  withRouter,
  translate(),
)(Default)
