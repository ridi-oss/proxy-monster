package athena

import (
	"context"
	"errors"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
)

func (t *target) catalogs(ctx context.Context) ([]string, error) {
	pages := awsa.NewListDataCatalogsPaginator(t.api, &awsa.ListDataCatalogsInput{WorkGroup: aws.String(t.config.workgroup)})
	seen := make(map[string]bool)
	tokens := make(map[string]bool)
	var names []string
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := checkMetadataToken(page.NextToken, tokens); err != nil {
			return nil, err
		}
		for _, catalog := range page.DataCatalogsSummary {
			name := aws.ToString(catalog.CatalogName)
			if name == "" || seen[name] {
				return nil, errors.New("athena: missing or duplicate catalog metadata")
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (t *target) databases(ctx context.Context, catalog string) ([]string, error) {
	pages := awsa.NewListDatabasesPaginator(t.api, &awsa.ListDatabasesInput{CatalogName: aws.String(catalog), WorkGroup: aws.String(t.config.workgroup)})
	seen := make(map[string]bool)
	tokens := make(map[string]bool)
	var names []string
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := checkMetadataToken(page.NextToken, tokens); err != nil {
			return nil, err
		}
		for _, database := range page.DatabaseList {
			name := aws.ToString(database.Name)
			if name == "" || seen[name] {
				return nil, errors.New("athena: missing or duplicate database metadata")
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func checkMetadataToken(next *string, seen map[string]bool) error {
	if token := aws.ToString(next); token != "" {
		if seen[token] {
			return errors.New("athena: repeated metadata page token")
		}
		seen[token] = true
	}
	return nil
}
