--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.20
-- Dumped by pg_dump version 9.6.20

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: utility; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.utility (
    id integer NOT NULL,
    date timestamp without time zone NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    bank_description text NOT NULL
);


ALTER TABLE public.utility OWNER TO test;

--
-- Name: utility_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

CREATE SEQUENCE public.utility_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.utility_id_seq OWNER TO test;

--
-- Name: utility_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: test
--

ALTER SEQUENCE public.utility_id_seq OWNED BY public.utility.id;


--
-- Name: utility id; Type: DEFAULT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.utility ALTER COLUMN id SET DEFAULT nextval('public.utility_id_seq'::regclass);


--
-- Data for Name: utility; Type: TABLE DATA; Schema: public; Owner: test
--

COPY public.utility (id, date, name, description, bank_description) FROM stdin;
12	2021-02-22 12:03:00	NZ Police 	Police Government New Zealand bank information can be found here:\r\nhttps://www.police.govt.nz/advice-services/infringement-services/payments/pay-internet-banking	\t[{\r\n\t  "ref": "NZ: https://www.police.govt.nz/advice-services/infringement-services/payments/pay-internet-banking",\r\n\t  "name": "Police Infringement Bureau",\r\n\t  "account_number": "03-0049-0000802-27",\r\n\t  "fields": [{\r\n\t    "label": "Particulars",\r\n\t    "description": "Notice number",\r\n\t    "type": "text",\r\n\t    "allow_empty": false,\r\n\t    "target": "particulars"\r\n\t  }, {\r\n\t    "label": "Code",\r\n\t    "description": "Vehicle registration number",\r\n\t    "type": "text",\r\n\t    "allow_empty": false,\r\n\t    "target": ["code"]\r\n\t  }, {\r\n\t    "label": "Reference",\r\n\t    "description": "Driver license number (optional)",\r\n\t    "type": "text",\r\n\t    "allow_empty": false,\r\n\t    "target": ["reference"]\r\n\t  }]\r\n\t}]
1	2020-07-20 15:07:00	2Degrees		[{\n  "ref": "https://www.2degreesmobile.co.nz/termsofuse/broadband/broadband/direct-debit-authority-terms-and-conditions/",\n  "name": "2Degrees Broadband",\n  "account_number": "02-0820-0188002-000",\n  "fields": [{\n    "label": "Phone number",\n    "description": "Users 2Degrees phone number",\n    "type": "number",\n    "allow_empty": false,\n    "target": "particulars"\n  }, {\n    "label": "Broadband Account Number",\n    "description": "Users 2Degrees broadband account number",\n    "type": "number",\n    "allow_empty": false,\n    "target": ["reference"]\n  }]\n}]
4	2020-07-20 15:11:00	Meridian Energy		[{\r\n  "ref": "https://www.meridianenergy.co.nz/business/account-and-support/pay-bill/internet-banking",\r\n  "name": "Meridian Energy",\r\n  "account_number": "03-0502-0233680-007",\r\n  "fields": [{\r\n    "label": "Meridian Account Number",\r\n    "description": "Users Meridian account number",\r\n    "type": "number",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Meridian Account Name",\r\n    "description": "Users Meridian account name",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }, {\r\n    "label": "Meridian Customer Number",\r\n    "description": "Users Meridian customer number (Optional)",\r\n    "type": "number",\r\n    "allow_empty": true,\r\n    "target": ["code"]\r\n  }]\r\n}]
5	2020-07-20 15:11:00	Spark		[{\r\n  "ref": "https://www.spark.co.nz/help/account/bill/pay-bill/",\r\n  "name": "Spark",\r\n  "account_number": "01-1820-0000123-000",\r\n  "fields": [{\r\n    "label": "Spark Account Number",\r\n    "description": "Users Spark account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}]
7	2020-07-20 15:12:00	Vodafone	Vodafone New Zealand has a number of different bank accounts, see http://help.vodafone.co.nz/app/answers/detail/a_id/17702/~/pay-your-bill-using-internet-banking to determine which bank account to use.\t	[{\r\n  "name": "Vodafone A",\r\n  "account_number": "02-0248-0228009-024",\r\n  "fields": [{\r\n    "label": "User name",\r\n    "description": "Vodafone customer name",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Vodafone Account Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["code"]\r\n  }, {\r\n    "label": "Vodafone Phone Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}, {\r\n  "name": "Vodafone B",\r\n  "account_number": "01-0102-0108338-001",\r\n  "fields": [{\r\n    "label": "User name",\r\n    "description": "Vodafone customer name",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Vodafone Account Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["code"]\r\n  }, {\r\n    "label": "Vodafone Phone Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}, {\r\n  "name": "Vodafone C",\r\n  "account_number": "02-0100-0074189-000",\r\n  "fields": [{\r\n    "label": "User name",\r\n    "description": "Vodafone customer name",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Vodafone Account Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["code"]\r\n  }, {\r\n    "label": "Vodafone Phone Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}, {\r\n  "name": "Vodafone D",\r\n  "account_number": "02-0108-0261413-000",\r\n  "fields": [{\r\n    "label": "User name",\r\n    "description": "Vodafone customer name",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Vodafone Account Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["code"]\r\n  }, {\r\n    "label": "Vodafone Phone Number",\r\n    "description": "Users Vodafone account number",\r\n    "type": "text",\r\n    "min_chars": 4,\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}]
2	2020-07-20 15:10:00	Contact Energy		[{\r\n  "ref": "https://contact.co.nz/residential/billing-and-payments#Pay-via-internet-banking",\r\n  "name": "Contact Energy",\r\n  "account_number": "03-0502-0223829-003",\r\n  "fields": [{\r\n    "label": "Contact Account Number",\r\n    "description": "Users Contact account number",\r\n    "type": "number",\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}, {\r\n  "name": "Rockgas",\r\n  "account_number": "02-0544-0241419-000",\r\n  "fields": [{\r\n    "label": "Rockgas Account Number",\r\n    "description": "Users Rockgas account number",\r\n    "type": "number",\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}]
6	2020-07-20 15:11:00	Trustpower Ltd		[{\r\n  "ref": "https://ask.trustpower.co.nz/app/answers/detail/a_id/26/",\r\n  "name": "Trustpower Ltd",\r\n  "account_number": "01-1839-0329105-001",\r\n  "fields": [{\r\n    "label": "Trustpower Ltd account number",\r\n    "description": "Users Trustpower Ltd account number",\r\n    "type": "number",\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}]
3	2020-07-20 15:10:00	Mercury NZ Limited	Mercury NZ Limited bank information can be found here: https://www.mercury.co.nz/help/faq/how-to-pay-my-bill	[{\n  "ref": "https://www.mercury.co.nz/help/faq/how-to-pay-my-bill",\n  "name": "Mercury NZ Limited",\n  "account_number": "12-3013-0893681-000",\n  "fields": [{\n    "label": "Mercury Account Number",\n    "description": "Users Mercury account number",\n    "type": "number",\n    "allow_empty": false,\n    "target": "particulars"\n  }, {\n    "label": "Mercury Account Name",\n    "description": "First two initials and your surname (or your business name) here e.g. JT Smith or JT Business Ltd",\n    "type": "text",\n    "allow_empty": false,\n    "target": ["reference"]\n  }]\n}]
13	2021-02-22 12:14:00	Ministry of Justice New Zealand	Ministry of Justice - Fines internet banking information can be here:\r\nhttps://www.justice.govt.nz/fines/about-fines/ways-to-pay-a-fine/pay-a-fine-by-internet-banking/	[{\r\n  "ref": "NZ: https://www.police.govt.nz/advice-services/infringement-services/payments/pay-internet-banking",\r\n  "name": "Ministry of Justice - Fines",\r\n  "account_number": "03-0049-0001055-01",\r\n  "fields": [{\r\n    "label": "Particulars",\r\n    "description": "The last name and initials of the person who owes the fines (for example, SMITH JS). If you are an employer making bulk payments, put your company name.",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": "particulars"\r\n  }, {\r\n    "label": "Code",\r\n    "description": "The letter 'P' then your 10-digit fine (PPN) number (for example, P1234567890). You can find your PPN on any letter about the fine. For bulk payments, put 'Salary/Wages'.",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": ["code"]\r\n  }, {\r\n    "label": "Reference",\r\n    "description": "The word FINES",\r\n    "type": "text",\r\n    "allow_empty": false,\r\n    "target": ["reference"]\r\n  }]\r\n}]
\.


--
-- Name: utility_id_seq; Type: SEQUENCE SET; Schema: public; Owner: test
--

SELECT pg_catalog.setval('public.utility_id_seq', 13, true);


--
-- Name: utility utility_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.utility
    ADD CONSTRAINT utility_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

