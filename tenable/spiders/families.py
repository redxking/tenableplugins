import scrapy
from tenable.items import TenableItem


class Nessus(scrapy.Spider):
    name = "families"
 
    def start_requests(self):
        urls = [
            'https://www.tenable.com/plugins/nessus/families',
            'https://www.tenable.com/plugins/was/families',
            'https://www.tenable.com/plugins/nnm/families',
            'https://www.tenable.com/plugins/lce/families',
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        base_url = 'https://www.tenable.com'

        for href in response.xpath('//table[@class]/tbody/tr/td/a/@href').extract():
            url = base_url + href
            yield scrapy.Request(url, callback=self.pageinate)

    def pageinate(self, response):
        next_page = response.xpath('//p[@class="pager--totals text-center"]/text()').extract()[3]
        for page in range(1, int(next_page) + 1):
            old_url = response.url +'?page='+ str(page)
            yield scrapy.Request(old_url, callback=self.get_id_links)


    def get_id_links(self, response):
        base_url = 'https://www.tenable.com'

        for href in response.xpath('//table[@class]/tbody/tr/td/a/@href').extract():
            url = base_url + href
            yield scrapy.Request(url, callback=self.scrap_data)
    

    def scrap_data(self, response):
        items = TenableItem()
        xpath_str = '//div/p/strong[contains(., "{}")]/following-sibling::span/text()'.format
        items['name'] = response.xpath('//div[@class="plugin-single"]/h1/text()').get()
        items['severity'] = response.xpath('//p/span[@class="u-m-r-1 badge badge--high"]/text()').get()
        items['synopsis'] = response.xpath('//div[@class="col-md-8"]/section[1]/span/text()').get()

        description = ''

        for i in response.xpath('//div[@class="col-md-8"]/section[2]/span/text()').extract():
            description += i
        items['description'] = description

        solution = ''
        for i in response.xpath('//div[@class="col-md-8"]/section[3]/span/text()').extract():
            solution += i
        items['solution'] = solution

        items['see_also'] = response.xpath('//div[@class="col-md-8"]/section[4]/p/a/@href').extract()
        
        items['plugin_details'] = {
            'severity': response.xpath('//p/span[@class="u-m-r-1 badge badge--high"]/text()').get(),
            'id': response.xpath(xpath_str('ID')).get(),
            'file_name': response.xpath(xpath_str('File Name')).extract(),
            'version': response.xpath(xpath_str('Version')).extract(),
            'type': response.xpath(xpath_str('Type')).extract(),
            'agent': response.xpath('//section/p/strong[contains(., "Agent")]/following-sibling::span/text()').extract(),
            'family': response.xpath('//div/p/strong[contains(., "Family")]/following-sibling::span/a/text()').extract(),
            'published': response.xpath(xpath_str('Published')).extract(),
            'updated': response.xpath(xpath_str('Updated')).extract(),
            'dependencies': response.xpath('//section/p/strong[contains(., "Dependencies")]/following-sibling::span/a/text()').extract(),
        }

        items['risk_info'] = {
            "risk_factor": response.xpath(xpath_str('Risk Factor')).extract(),
        }
        items['cvss_v2'] = {
            'base_score': response.xpath(xpath_str('Base Score')).extract()[0] if len(response.xpath(xpath_str('Base Score')).extract()) > 0 else None ,
            'temporal_score': response.xpath(xpath_str('Temporal Score')).extract()[0] if len(response.xpath(xpath_str('Temporal Score')).extract()) > 0 else None,
            'vector': response.xpath(xpath_str('Vector')).extract()[0] if len(response.xpath(xpath_str('Vector')).extract()) > 0 else None,
            'temporal_vector': response.xpath(xpath_str('Temporal Vector')).extract()[0] if len(response.xpath(xpath_str('Temporal Vector')).extract()) > 0 else None,

        }
        items['cvss_v3'] = {
            'base_score': response.xpath(xpath_str('Base Score')).extract()[1] if len(response.xpath(xpath_str('Base Score')).extract()) > 1 else None ,
            'temporal_score': response.xpath(xpath_str('Temporal Score')).extract()[1] if len(response.xpath(xpath_str('Temporal Score')).extract()) > 1 else None,
            'vector': response.xpath(xpath_str('Vector')).extract()[1] if len(response.xpath(xpath_str('Vector')).extract()) > 1 else None,
            'temporal_vector': response.xpath(xpath_str('Temporal Vector')).extract()[1] if len(response.xpath(xpath_str('Temporal Vector')).extract()) > 1 else None,
        }
        xpath_vi = '//section/section/p/strong[contains(., "{}")]/following-sibling::span/text()'.format

        items['vulnerability_info'] = {
            'cep': response.xpath(xpath_vi('CPE')).extract(),
            'exploit_available': response.xpath('//section/div/p/strong[contains(., "Exploit Available")]/following-sibling::span/text()').get(),
            'exploit_ease': response.xpath('//section/div/p/strong[contains(., "Exploit Ease")]/following-sibling::span/text()').get(),
            'required_kb_tems': response.xpath(xpath_vi('Required KB Items')).extract(),
            'patch_publication_date': response.xpath('//section/div/p/strong[contains(., "Patch Publication Date")]/following-sibling::span/text()').get(),
            'vulnerability_publication_date': response.xpath('//section/div/p/strong[contains(., "Vulnerability Publication Date")]/following-sibling::span/text()').extract(),
            'cep': response.xpath(xpath_vi('CPE')).extract(),
            'cep': response.xpath(xpath_vi('CPE')).extract(),
        }
        items['reference_info'] = {
            'cve': response.xpath("//section/section/p/strong[contains(., 'CVE')]/following-sibling::span/a/text()").extract(),
            'bid': response.xpath("//section/section/p/strong[contains(., 'BID')]/following-sibling::span/a/text()").extract(),
            'secunia': response.xpath("//section/div/section/p/strong[contains(., 'Secunia')]/following-sibling::span/a/text()").extract(),
            'cwe': response.xpath("//section/div/section/p/strong[contains(., 'CWE')]/following-sibling::span/a/text()").extract(),
        }

        yield items
