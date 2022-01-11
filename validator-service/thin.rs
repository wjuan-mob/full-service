// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Connection implementations required for the Thin client.
//! The unattested client implementation.

use cookie::{Cookie, CookieJar, ParseError};
use displaydoc::Display;
use grpcio::{CallOption, ChannelBuilder, Environment, Error as GrpcError, MetadataBuilder, Metadata};
use mc_common::{
    logger::{log, o, Logger},
    trace_time,
};
use mc_connection::{AttestationError,
    AuthenticationError, CredentialsProvider, CredentialsProviderError,
    Error, Result,
    BlockInfo, BlockchainConnection, Connection,
};
use mc_consensus_api::{
    consensus_common::BlocksRequest, consensus_common_grpc::BlockchainApiClient, empty::Empty,
};
use mc_transaction_core::{Block, BlockID, BlockIndex};
use mc_util_grpc::{ConnectionUriGrpcioChannel};
use mc_util_uri::{ConnectionUri, ConsensusClientUri as ClientUri, UriConversionError};
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
    result::Result as StdResult,
    sync::Arc,
    string::FromUtf8Error,

};
/// Attestation failures a thick client can generate
#[derive(Debug, Display)]
pub enum ThinClientError {
    /// gRPC failure in attestation: {0}
    Grpc(GrpcError),
    /// Could not create ResponderID from URI {0}: {1}
    InvalidResponderID(String, UriConversionError),
    /// Unexpected Error Converting URI {0}
    UriConversionError(UriConversionError),
    /// Credentials provider error: {0}
    CredentialsProvider(Box<dyn CredentialsProviderError + 'static>),
}

impl From<GrpcError> for ThinClientError {
    fn from(src: GrpcError) -> Self {
        ThinClientError::Grpc(src)
    }
}

impl From<UriConversionError> for ThinClientError {
    fn from(src: UriConversionError) -> Self {
        match src.clone() {
            UriConversionError::ResponderId(uri, _err) => {
                ThinClientError::InvalidResponderID(uri, src)
            }
            _ => ThinClientError::UriConversionError(src),
        }
    }
}

impl From<Box<dyn CredentialsProviderError + 'static>> for ThinClientError {
    fn from(src: Box<dyn CredentialsProviderError + 'static>) -> Self {
        Self::CredentialsProvider(src)
    }
}

impl AuthenticationError for ThinClientError {
    fn is_unauthenticated(&self) -> bool {
        match self {
            Self::Grpc(grpc_error) => grpc_error.is_unauthenticated(),
            _ => false,
        }
    }
}

impl AttestationError for ThinClientError {}

/// A connection from a client to a consensus enclave.
pub struct ThinClient<CP: CredentialsProvider> {
    /// The destination's URI
    uri: ClientUri,
    /// The logging instance
    logger: Logger,
    /// The gRPC API client we will use for blockchain detail retrieval.
    blockchain_api_client: BlockchainApiClient,
    /// Generic interface for retreiving GRPC credentials.
    credentials_provider: CP,
    /// A hash map of metadata to set on outbound requests, filled by inbound
    /// `Set-Cookie` metadata
    cookies: CookieJar,
}

impl<CP: CredentialsProvider> ThinClient<CP> {
    /// Create a new unattested connection to the given consensus node.
    pub fn new(
        uri: ClientUri,
        env: Arc<Environment>,
        credentials_provider: CP,
        logger: Logger,
    ) -> Result<Self> {
        let logger = logger.new(o!("mc.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let blockchain_api_client = BlockchainApiClient::new(ch.clone());

        Ok(Self {
            uri,
            logger,
            blockchain_api_client,
            credentials_provider,
            cookies: CookieJar::default(),
        })
    }

    /// A wrapper for performing an authenticated call. This also takes care to
    /// properly include cookie information in the request.
    fn authenticated_call<T>(
        &mut self,
        func: impl FnOnce(&mut Self, CallOption) -> StdResult<T, GrpcError>,
    ) -> StdResult<T, ThinClientError> {
        // Make the actual RPC call.
        let call_option = self.call_option()?;
        let result = func(self, call_option);

        // If the call failed due to authentication (credentials) error, reset creds so
        // that it gets re-created on the next call.
        if let Err(err) = result.as_ref() {
            if err.is_unauthenticated() {
                self.credentials_provider.clear();
            }
        }
        Ok(result?)
    }

    //What does this do?
    fn call_option(&self) -> StdResult<CallOption, Box<dyn CredentialsProviderError + 'static>> {
        let retval = CallOption::default();

        // Create metadata from cookies and credentials
        let mut metadata_builder = self
            .cookies
            .to_client_metadata()
            .unwrap_or_else(|_| MetadataBuilder::new());

        if let Some(creds) = self
            .credentials_provider
            .get_credentials()
            .map_err(|err| -> Box<dyn CredentialsProviderError + 'static> { Box::new(err) })?
        {
            if !creds.username().is_empty() && !creds.password().is_empty() {
                metadata_builder
                    .add_str("Authorization", &creds.authorization_header())
                    .expect("Error setting authorization header");
            }
        }

        Ok(retval.headers(metadata_builder.build()))
    }
}

impl<CP: CredentialsProvider> Connection for ThinClient<CP> {
    type Uri = ClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<CP: CredentialsProvider + Clone> Clone for ThinClient<CP> {
    fn clone(&self) -> Self {
        Self {
            uri: self.uri.clone(),
            logger: self.logger.clone(),
            blockchain_api_client: self.blockchain_api_client.clone(),
            credentials_provider: self.credentials_provider.clone(),
            cookies: CookieJar::default(),
        }
    }
}

impl<CP: CredentialsProvider> BlockchainConnection for ThinClient<CP> {
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> Result<Vec<Block>> {
        trace_time!(self.logger, "ThinClient::get_blocks");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit = u32::try_from(range.end - range.start).or(Err(Error::RequestTooLarge))?;
        request.set_limit(limit);

        self.authenticated_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_blocks_full(&request, call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?
        .get_blocks()
        .iter()
        .map(|proto_block| Block::try_from(proto_block).map_err(Error::from))
        .collect::<Result<Vec<Block>>>()
    }

    fn fetch_block_ids(&mut self, range: Range<BlockIndex>) -> Result<Vec<BlockID>> {
        trace_time!(self.logger, "ThinClient::get_block_ids");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit = u32::try_from(range.end - range.start).or(Err(Error::RequestTooLarge))?;
        request.set_limit(limit);

        self.authenticated_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_blocks_full(&request, call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?
        .get_blocks()
        .iter()
        .map(|proto_block| BlockID::try_from(proto_block.get_id()).map_err(Error::from))
        .collect::<Result<Vec<BlockID>>>()
    }

    fn fetch_block_height(&mut self) -> Result<BlockIndex> {
        trace_time!(self.logger, "ThinClient::fetch_block_height");

        Ok(self
            .authenticated_call(|this, call_option| {
                let (header, message, trailer) = this
                    .blockchain_api_client
                    .get_last_block_info_full(&Empty::new(), call_option)?;

                // Update cookies from server-sent metadata
                if let Err(e) = this
                    .cookies
                    .update_from_server_metadata(header.as_ref(), trailer.as_ref())
                {
                    log::warn!(
                        this.logger,
                        "Could not update cookies from gRPC metadata: {}",
                        e
                    )
                }

                Ok(message)
            })?
            .index)
    }

    fn fetch_block_info(&mut self) -> Result<BlockInfo> {
        trace_time!(self.logger, "ThinClient::fetch_block_height");

        let block_info = self.authenticated_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_last_block_info_full(&Empty::new(), call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?;

        Ok(block_info.into())
    }
}

impl<CP: CredentialsProvider> Display for ThinClient<CP> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<CP: CredentialsProvider> Eq for ThinClient<CP> {}

impl<CP: CredentialsProvider> Hash for ThinClient<CP> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl<CP: CredentialsProvider> PartialEq for ThinClient<CP> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<CP: CredentialsProvider> Ord for ThinClient<CP> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<CP: CredentialsProvider> PartialOrd for ThinClient<CP> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

fn append_to_cookies(dest: &mut Vec<Cookie>, src: Option<&Metadata>) -> Result<()> {
    if let Some(metadata) = src {
        for (name, value) in metadata {
            if name.eq_ignore_ascii_case("set-cookie") {
                let stringvalue = String::from_utf8(value.to_vec())?;
                dest.push(Cookie::parse(stringvalue)?);
            }
        }
    }
    Ok(())
}

impl From<ParseError> for Error {
    fn from(src: ParseError) -> Error {
        Error::Parse(src)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(src: FromUtf8Error) -> Error {
        Error::Utf8(src)
    }
}
/// A trait used to monkey-patch helper methods onto the `cookie::CookieJar`
/// type.
pub trait GrpcCookieStore {
    /// Search metadata received from a server and treat any `Set-Cookie` values
    /// appropriately.
    fn update_from_server_metadata(
        &mut self,
        headers: Option<&Metadata>,
        trailers: Option<&Metadata>,
    ) -> Result<()>;

    /// Copy the contents of this CookieJar into a Metadata structure containing
    /// any `Cookie` headers to send to a server.
    fn to_client_metadata(&self) -> Result<MetadataBuilder>;
}

impl GrpcCookieStore for CookieJar {
    fn update_from_server_metadata(
        &mut self,
        header: Option<&Metadata>,
        trailer: Option<&Metadata>,
    ) -> Result<()> {
        let mut cookies = Vec::new();
        append_to_cookies(&mut cookies, header)?;
        append_to_cookies(&mut cookies, trailer)?;

        for cookie in cookies {
            self.add(cookie);
        }
        Ok(())
    }

    fn to_client_metadata(&self) -> Result<MetadataBuilder> {
        let mut builder = MetadataBuilder::new();

        for cookie in self.iter() {
            builder.add_str("Cookie", cookie.to_string().as_str())?;
        }

        Ok(builder)
    }
}