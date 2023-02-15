import React from 'react';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Typography from '@mui/material/Typography';
import ClaimSet from '../ClaimSet';
import Link from '@mui/material/Link';

interface ItemProps {
  children?: string | JSX.Element | JSX.Element[]
  title?: string
  secondary?: string
}

function Item({ children, title, secondary }: ItemProps) {
  return (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}
        aria-controls="panel1a-content"
        id="panel1a-header">
        <Typography sx={{ width: '33%', flexShrink: 0 }}>{title}</Typography>
        {secondary && <Typography sx={{ color: 'text.secondary' }}>{secondary}</Typography>}
      </AccordionSummary>
      <AccordionDetails>
        {children}
      </AccordionDetails>
    </Accordion>
  );
}

export interface ExplanationProps {
  claims: ClaimSet
}

export default function ChainOfTrust(props: ExplanationProps): JSX.Element {
  const { claims } = props;
  const { ass } = claims.emblem.payload;
  const issURL = new URL(claims.internals[0].payload.iss);
  return (
    <div>
      <Item title='Protected Entity' >
        <Typography>
          Assets marked as protected:
        </Typography>
        <ul>{(ass as string[]).map((a) => <li key={a}>{a}</li>)}</ul>
      </Item>
      <Item title='Emblem issuer' secondary={issURL.host}>
        <Typography>
          Identity: <Link href={issURL.toString()}>{issURL.host}</Link>
          <br/>
          <Typography variant="caption" noWrap={true}>
            Verification key: <Link href={`https://${claims.internals[0].verificationKID}.adem-configuration.${issURL.host}`}>
              {claims.internals[0].verificationKID}
            </Link>
          </Typography>
        </Typography>
      </Item>
      {claims.externals.length && <Item title='Endorsing organizations' secondary={`(${claims.externals.length} in total)`}>
        <ul>
          {claims.externals.map((el, i) => {
            const extIssURL = new URL(el.payload.iss);
            return (
              <li key={extIssURL.host}>
                Organization: <Link href={extIssURL.toString()}>
                  {extIssURL.host}
                </Link>
                <br/>
                <Typography variant="caption" noWrap={true}>
                  Verification key: <Link href={`https://${el.verificationKID}.adem-configuration.${extIssURL.host}`}>
                    {el.verificationKID}
                  </Link>
                </Typography>
              </li>
            );
          })}
        </ul>
      </Item>}
    </div>
  );
}
