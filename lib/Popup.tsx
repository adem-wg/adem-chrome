import { parseTXTs } from './parsing';
import React from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import { IP_STATUS } from './status';
import { Message } from '../background';
import ChainOfTrust from './components/ChainOfTrust';
import { queryTXT } from './util/dns';
import ipaddr from 'ipaddr.js';
import { allFulfilled } from './util/promise';
import Divider from '@mui/material/Divider';
import { IP } from './Constraints';

interface PopupProps {
  url?: string
}

interface PopupState {
  details?: JSX.Element
  checked: boolean
  labelled: boolean
  error?: Error | null
}

class Popup extends React.Component<PopupProps, PopupState> {
  constructor(props: PopupProps) {
    super(props);
    this.state = {
      checked: false,
      labelled: false,
      error: null,
    };
  }

  handleError(error: Error) {
    this.setState({ error });
  }

  componentDidMount() {
    const { url } = this.props;
    if (!url) {
      return;
    }

    // Handle background.js responses
    chrome.runtime.onMessage.addListener(
      (response, sender, sendResponse) => this.handleIpResponse(response),
    );
    // Request IP from background.js
    chrome.runtime.sendMessage(url, (response) => this.handleIpResponse(response));
  }

  async checkTXTForEmblem(ip: IP) {
    try {
      const { url } = this.props;
      const sets = await queryTXT(url as string)
        .then(parseTXTs)
        .then((sets) => allFulfilled(
          sets.map((set) => set.verify()),
          (r) => {
            console.error(`could not verify claim set: ${r}`);
            if (r instanceof Error) {
              console.error(r);
            }
          })
        );

      const match = sets.find((set) =>set.emblem.marks(ip));
      if (match === undefined) {
        this.setState({ checked: true, labelled: false });
      } else {
        this.setState({
          checked: true,
          labelled: true,
          details: <ChainOfTrust claims={match} />,
        });
      }
    } catch (error) {
      if (error instanceof Error) {
        this.handleError(error);
      }
    }
  }

  handleIpResponse(response: Message) {
    const { status, ip } = response;
    if (status === IP_STATUS.NO_REQUEST) {
      this.handleError(new Error('no request logged'));
    } else if (status === IP_STATUS.RESOLVED) {
      try {
        if (ip === undefined) {
          throw new Error('IP resolved but no IP given')
        }
        this.checkTXTForEmblem(ipaddr.parse(ip));
      } catch (e) {
        this.handleError(e as Error);
      }
    }
    // else: pending. Background will remember this tab and send message later.
  }

  render() {
    const { url } = this.props;
    const { checked, error, labelled, details } = this.state;
    let info;
    if (!url) {
      info = <Alert severity="info">Browse to a site to check ADEM.</Alert>;
    } else if (error) {
      console.error(error);
      info = <Alert severity='error'>There was an error.</Alert>;
    } else if (!checked) {
      info = (<Box>
        <Typography>Checking for emblems...</Typography>
        <Box sx={{ my: 2 }} style={{display: 'flex', justifyContent: 'center'}}>
          <CircularProgress />
        </Box>
      </Box>);
    } else { // !error && url && ip && checked
      if (labelled) {
        info = <Alert severity="success">This site is labelled with ADEM.</Alert>;
      } else {
        info = <Alert severity="info">This site is not labelled with ADEM.</Alert>;
      }
    }

    return <Container sx={{ minWidth: 300 }}>
      <Typography variant="h5" gutterBottom>
        ADEM DNS Checker
      </Typography>
      <Box>
        <Box sx={{ my: 2 }}>
          {info}
        </Box>
        {details && <Divider variant="middle" />}
        <Box sx={{ my: 2 }}>
          {details}
        </Box>
      </Box>
    </Container>;
  }
}
export default Popup;
